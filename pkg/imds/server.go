// Copyright 2026 The Athenz Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package imds serves AWS credentials from a local file or ZTS through IMDSv2.
package imds

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	maxTokenTTL = 21600
	rolePath    = "/latest/meta-data/iam/security-credentials/"
)

type config struct {
	addr            string
	source          string
	role            string
	credentialsFile string
	ztsEndpoint     string
	domain          string
	certFile        string
	keyFile         string
	caFile          string
	duration        int32
}

func parseConfig(args []string) (config, error) {
	var cfg config
	var duration int64
	flags := flag.NewFlagSet("imds", flag.ContinueOnError)
	flags.StringVar(&cfg.addr, "listen", "127.0.0.1:1338", "IMDSv2 listen address")
	flags.StringVar(&cfg.source, "source", "", "credentials source: file or zts")
	flags.StringVar(&cfg.role, "role", "", "role name exposed by IMDSv2")
	flags.StringVar(&cfg.credentialsFile, "credentials-file", "", "AWS shared credentials file (file source)")
	flags.StringVar(&cfg.ztsEndpoint, "zts-endpoint", "", "ZTS endpoint (zts source)")
	flags.StringVar(&cfg.domain, "domain", "", "Athenz domain (zts source)")
	flags.StringVar(&cfg.certFile, "cert-file", "", "client certificate (zts source)")
	flags.StringVar(&cfg.keyFile, "key-file", "", "client key (zts source)")
	flags.StringVar(&cfg.caFile, "ca-file", "", "ZTS CA certificate (zts source)")
	flags.Int64Var(&duration, "duration-seconds", 0, "requested AWS credential lifetime (zts source)")
	if err := flags.Parse(args); err != nil {
		return cfg, err
	}
	if flags.NArg() != 0 || cfg.role == "" || strings.Contains(cfg.role, "/") {
		return cfg, fmt.Errorf("imds requires one role name without a slash and no positional arguments")
	}
	if cfg.source == "file" && cfg.credentialsFile == "" {
		return cfg, fmt.Errorf("file source requires -credentials-file")
	}
	if cfg.source == "zts" && (cfg.ztsEndpoint == "" || cfg.domain == "" || cfg.certFile == "" || cfg.keyFile == "") {
		return cfg, fmt.Errorf("zts source requires -zts-endpoint, -domain, -cert-file, and -key-file")
	}
	if cfg.source == "zts" && !strings.HasPrefix(cfg.ztsEndpoint, "https://") {
		return cfg, fmt.Errorf("zts source requires an HTTPS endpoint")
	}
	if cfg.source != "file" && cfg.source != "zts" {
		return cfg, fmt.Errorf("imds source must be file or zts")
	}
	if duration < 0 || duration > 2147483647 {
		return cfg, fmt.Errorf("duration-seconds must be between 0 and 2147483647")
	}
	cfg.duration = int32(duration)
	return cfg, nil
}

// Run starts the standalone IMDSv2 server. It is an opt-in SIA subcommand, so
// normal identity and token provisioning retain their existing behavior.
func Run(ctx context.Context, args []string) error {
	cfg, err := parseConfig(args)
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	if err != nil {
		return err
	}
	var source credentialSource
	if cfg.source == "file" {
		source = fileSource{path: cfg.credentialsFile}
	} else {
		source, err = newZTSSource(cfg)
		if err != nil {
			return err
		}
	}
	listener, err := net.Listen("tcp", cfg.addr)
	if err != nil {
		return err
	}
	server := &http.Server{
		Handler:           newHandler(cfg.role, source),
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	err = server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

type handler struct {
	role   string
	source credentialSource
	mu     sync.Mutex
	tokens map[string]time.Time
}

func newHandler(role string, source credentialSource) http.Handler {
	return &handler{role: role, source: source, tokens: make(map[string]time.Time)}
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.URL.Path == "/latest/api/token" {
		if r.Method != http.MethodPut {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		h.putToken(w, r)
		return
	}
	if r.URL.Path != rolePath && r.URL.Path != rolePath+h.role {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !h.hasToken(r.Header.Get("X-aws-ec2-metadata-token")) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if r.URL.Path == rolePath {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = fmt.Fprintln(w, h.role)
		return
	}
	creds, err := h.source.Get(r.Context())
	if err != nil || creds.AccessKeyID == "" || creds.SecretAccessKey == "" || !creds.Expiration.After(time.Now()) {
		http.Error(w, "credentials unavailable", http.StatusServiceUnavailable)
		return
	}
	response := struct {
		Code            string `json:"Code"`
		AccessKeyID     string `json:"AccessKeyId"`
		SecretAccessKey string `json:"SecretAccessKey"`
		Token           string `json:"Token,omitempty"`
		Expiration      string `json:"Expiration"`
	}{
		Code:            "Success",
		AccessKeyID:     creds.AccessKeyID,
		SecretAccessKey: creds.SecretAccessKey,
		Token:           creds.SessionToken,
		Expiration:      creds.Expiration.UTC().Format(time.RFC3339),
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

func (h *handler) putToken(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Forwarded-For") != "" {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	ttl, err := strconv.Atoi(r.Header.Get("X-aws-ec2-metadata-token-ttl-seconds"))
	if err != nil || ttl < 1 || ttl > maxTokenTTL {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	token := base64.RawURLEncoding.EncodeToString(random)
	until := time.Now().Add(time.Duration(ttl) * time.Second)
	h.mu.Lock()
	for old, expiry := range h.tokens {
		if !expiry.After(time.Now()) || len(h.tokens) >= 128 {
			delete(h.tokens, old)
		}
	}
	h.tokens[token] = until
	h.mu.Unlock()
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("X-aws-ec2-metadata-token-ttl-seconds", strconv.Itoa(ttl))
	_, _ = fmt.Fprint(w, token)
}

func (h *handler) hasToken(token string) bool {
	if token == "" {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	until, found := h.tokens[token]
	if found && !until.After(time.Now()) {
		delete(h.tokens, token)
		return false
	}
	return found
}
