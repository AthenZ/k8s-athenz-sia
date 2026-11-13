// Copyright 2023 LY Corporation
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
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/AthenZ/k8s-athenz-sia/v3/pkg/config"
	"github.com/AthenZ/k8s-athenz-sia/v3/pkg/daemon"
	"github.com/AthenZ/k8s-athenz-sia/v3/third_party/log"
)

const (
	maxTokenTTL = 21600
	rolePath    = "/latest/meta-data/iam/security-credentials/"
)

type service struct {
	server   *http.Server
	listener net.Listener
	wg       sync.WaitGroup
}

// New configures an optional IMDSv2 server alongside SIA's other services.
func New(ctx context.Context, idCfg *config.IdentityConfig) (daemon.Daemon, error) {
	s := &service{}
	if ctx.Err() != nil || idCfg.Init || !idCfg.IMDSServer.Use {
		return s, nil
	}
	cfg := idCfg.IMDSServer
	host, _, err := net.SplitHostPort(cfg.Addr)
	ip := net.ParseIP(host)
	if err != nil || ip == nil || !ip.IsLoopback() {
		return nil, fmt.Errorf("IMDSv2 server requires a loopback listen address")
	}
	if cfg.Role == "" || strings.Contains(cfg.Role, "/") {
		return nil, fmt.Errorf("IMDSv2 server requires one role name without a slash")
	}
	if cfg.DurationSeconds < 0 || cfg.DurationSeconds > 2147483647 {
		return nil, fmt.Errorf("IMDSv2 duration must be between 0 and 2147483647 seconds")
	}
	var source credentialSource
	switch cfg.Source {
	case "file":
		if cfg.CredentialsFile == "" {
			return nil, fmt.Errorf("IMDSv2 file source requires a credentials file")
		}
		source = fileSource{path: cfg.CredentialsFile}
	case "zts":
		if cfg.Domain == "" || idCfg.Endpoint == "" || !strings.HasPrefix(idCfg.Endpoint, "https://") || idCfg.Reloader == nil {
			return nil, fmt.Errorf("IMDSv2 ZTS source requires a domain, HTTPS endpoint, and client certificate")
		}
		source, err = newZTSSource(idCfg)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("IMDSv2 source must be file or zts")
	}
	s.server = &http.Server{
		Addr:              cfg.Addr,
		Handler:           newHandler(cfg.Role, source),
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	return s, nil
}

func (s *service) Start(ctx context.Context) error {
	if ctx.Err() != nil || s.server == nil {
		return nil
	}
	listener, err := net.Listen("tcp", s.server.Addr)
	if err != nil {
		return err
	}
	s.listener = listener
	log.Infof("Starting IMDSv2 server[%s]", listener.Addr())
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		if err := s.server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("Failed to serve IMDSv2: %s", err)
		}
		log.Info("Stopped IMDSv2 server")
	}()
	return nil
}

func (s *service) Shutdown() {
	if s.server == nil {
		return
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.server.Shutdown(shutdownCtx); err != nil {
		log.Errorf("Failed to stop IMDSv2 server: %s", err)
	}
	s.wg.Wait()
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
