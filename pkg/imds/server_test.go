package imds

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type testSource struct{ value credentials }

func (s testSource) Get(context.Context) (credentials, error) { return s.value, nil }

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
