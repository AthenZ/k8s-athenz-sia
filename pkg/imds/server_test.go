package imds

import (
	"context"
	"encoding/json"
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
