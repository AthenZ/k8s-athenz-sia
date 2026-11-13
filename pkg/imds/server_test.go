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

package imds

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/AthenZ/k8s-athenz-sia/v3/pkg/config"
	"github.com/AthenZ/k8s-athenz-sia/v3/third_party/log"
)

type testSource struct{ value credentials }

func (s testSource) Get(context.Context) (credentials, error) { return s.value, nil }

type failingSource struct{}

func (failingSource) Get(context.Context) (credentials, error) {
	return credentials{}, errors.New("credential source unavailable")
}

func TestIMDSServerRejectsInvalidConfiguration(t *testing.T) {
	base := config.IdentityConfig{IMDSServer: config.IMDSServerConfig{
		Use: true, Addr: "127.0.0.1:0", Source: "file",
		Role: "app", CredentialsFile: "/unused/credentials",
	}}
	for _, tc := range []struct {
		name   string
		change func(*config.IdentityConfig)
		want   string
	}{
		{"non-loopback address", func(c *config.IdentityConfig) { c.IMDSServer.Addr = "0.0.0.0:1338" }, "loopback"},
		{"hostname", func(c *config.IdentityConfig) { c.IMDSServer.Addr = "localhost:1338" }, "loopback"},
		{"missing role", func(c *config.IdentityConfig) { c.IMDSServer.Role = "" }, "role name"},
		{"role path", func(c *config.IdentityConfig) { c.IMDSServer.Role = "other/role" }, "role name"},
		{"negative duration", func(c *config.IdentityConfig) { c.IMDSServer.DurationSeconds = -1 }, "duration"},
		{"long duration", func(c *config.IdentityConfig) { c.IMDSServer.DurationSeconds = 2147483648 }, "duration"},
		{"missing file", func(c *config.IdentityConfig) { c.IMDSServer.CredentialsFile = "" }, "credentials file"},
		{"unsupported source", func(c *config.IdentityConfig) { c.IMDSServer.Source = "unknown" }, "source"},
		{"incomplete ZTS source", func(c *config.IdentityConfig) { c.IMDSServer.Source = "zts" }, "ZTS source"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			tc.change(&cfg)
			_, err := New(context.Background(), &cfg)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q error, got %v", tc.want, err)
			}
		})
	}
}

func TestIMDSServerDisabledDuringInitOrCancellation(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  config.IdentityConfig
		ctx  context.Context
	}{
		{"disabled", config.IdentityConfig{}, context.Background()},
		{"init", config.IdentityConfig{Init: true, IMDSServer: config.IMDSServerConfig{Use: true}}, context.Background()},
		{"canceled", config.IdentityConfig{IMDSServer: config.IMDSServerConfig{Use: true}}, canceledContext()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			daemon, err := New(tc.ctx, &tc.cfg)
			if err != nil {
				t.Fatal(err)
			}
			if err := daemon.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			daemon.Shutdown()
		})
	}
}

func canceledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func TestIMDSv2Credentials(t *testing.T) {
	h := newHandler("showcaserole", testSource{credentials{
		AccessKeyID:     "local-key",
		SecretAccessKey: "local-secret",
		SessionToken:    "session-token",
		Expiration:      time.Now().Add(time.Hour),
	}})

	request := httptest.NewRequest(http.MethodGet, rolePath+"showcaserole", nil)
	response := httptest.NewRecorder()
	h.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("missing token: got %d", response.Code)
	}

	request = httptest.NewRequest(http.MethodPut, "/latest/api/token", nil)
	request.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "21600")
	response = httptest.NewRecorder()
	h.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("request token: got %d", response.Code)
	}
	token := response.Body.String()
	if token == "" {
		t.Fatal("empty IMDSv2 token")
	}

	request = httptest.NewRequest(http.MethodGet, rolePath, nil)
	request.Header.Set("X-aws-ec2-metadata-token", token)
	response = httptest.NewRecorder()
	h.ServeHTTP(response, request)
	if response.Code != http.StatusOK || strings.TrimSpace(response.Body.String()) != "showcaserole" {
		t.Fatalf("list roles: status %d, body %q", response.Code, response.Body.String())
	}

	request = httptest.NewRequest(http.MethodGet, rolePath+"showcaserole", nil)
	request.Header.Set("X-aws-ec2-metadata-token", token)
	response = httptest.NewRecorder()
	h.ServeHTTP(response, request)
	var body map[string]string
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &body) != nil {
		t.Fatalf("get credentials: status %d, body %q", response.Code, response.Body.String())
	}
	if body["Code"] != "Success" || body["AccessKeyId"] != "local-key" || body["SecretAccessKey"] != "local-secret" || body["Token"] != "session-token" || body["Expiration"] == "" {
		t.Fatalf("unexpected IMDS credentials: %v", body)
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("credential response must not be cached")
	}
}

func TestIMDSv2RejectsInvalidTokens(t *testing.T) {
	h := newHandler("zts", testSource{}).(*handler)
	for _, ttl := range []string{"", "0", "21601", "invalid"} {
		request := httptest.NewRequest(http.MethodPut, "/latest/api/token", nil)
		request.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", ttl)
		response := httptest.NewRecorder()
		h.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Errorf("TTL %q: got %d", ttl, response.Code)
		}
	}
	h.tokens["expired"] = time.Now().Add(-time.Second)
	request := httptest.NewRequest(http.MethodGet, rolePath+"zts", nil)
	request.Header.Set("X-aws-ec2-metadata-token", "expired")
	response := httptest.NewRecorder()
	h.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("expired token: got %d", response.Code)
	}
}

func TestIMDSv2RejectsInvalidRequests(t *testing.T) {
	h := newHandler("app", testSource{credentials{
		AccessKeyID: "key", SecretAccessKey: "secret",
		Expiration: time.Now().Add(time.Hour),
	}}).(*handler)
	h.tokens["valid"] = time.Now().Add(time.Minute)

	for _, tc := range []struct {
		name, method, path string
		headers            map[string]string
		want               int
	}{
		{"token method", http.MethodGet, "/latest/api/token", nil, http.StatusMethodNotAllowed},
		{"unknown path", http.MethodGet, "/other", nil, http.StatusNotFound},
		{"role method", http.MethodPost, rolePath + "app", nil, http.StatusMethodNotAllowed},
		{"proxy token request", http.MethodPut, "/latest/api/token", map[string]string{
			"X-Forwarded-For":                      "192.0.2.1",
			"X-aws-ec2-metadata-token-ttl-seconds": "60",
		}, http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(tc.method, tc.path, nil)
			for name, value := range tc.headers {
				request.Header.Set(name, value)
			}
			response := httptest.NewRecorder()
			h.ServeHTTP(response, request)
			if response.Code != tc.want {
				t.Fatalf("status = %d, want %d", response.Code, tc.want)
			}
		})
	}
}

func TestIMDSv2DoesNotServeUnavailableCredentials(t *testing.T) {
	for _, tc := range []struct {
		name   string
		source credentialSource
	}{
		{"source error", failingSource{}},
		{"missing key", testSource{credentials{Expiration: time.Now().Add(time.Hour)}}},
		{"expired", testSource{credentials{AccessKeyID: "key", SecretAccessKey: "secret", Expiration: time.Now().Add(-time.Minute)}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHandler("app", tc.source).(*handler)
			h.tokens["valid"] = time.Now().Add(time.Minute)
			request := httptest.NewRequest(http.MethodGet, rolePath+"app", nil)
			request.Header.Set("X-aws-ec2-metadata-token", "valid")
			response := httptest.NewRecorder()
			h.ServeHTTP(response, request)
			if response.Code != http.StatusServiceUnavailable {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusServiceUnavailable)
			}
		})
	}
}

func TestIMDSServerLifecycle(t *testing.T) {
	log.InitLogger("", "INFO", true)
	path := t.TempDir() + "/credentials"
	if err := os.WriteFile(path, []byte("[default]\naws_access_key_id=local-key\naws_secret_access_key=local-secret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	idCfg := &config.IdentityConfig{IMDSServer: config.IMDSServerConfig{
		Use:             true,
		Addr:            "127.0.0.1:0",
		Source:          "file",
		Role:            "zts",
		CredentialsFile: path,
	}}
	daemon, err := New(context.Background(), idCfg)
	if err != nil {
		t.Fatal(err)
	}
	s := daemon.(*service)
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Shutdown)
	request, err := http.NewRequest(http.MethodPut, "http://"+s.listener.Addr().String()+"/latest/api/token", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "60")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("token status = %d", response.StatusCode)
	}
}
