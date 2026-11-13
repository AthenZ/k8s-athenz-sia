package imds

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFileSourceReadsUpdatedCredentials(t *testing.T) {
	path := filepath.Join(t.TempDir(), "emulator_credentials")
	write := func(key string) {
		t.Helper()
		data := []byte("[default]\naws_access_key_id=" + key + "\naws_secret_access_key=secret\n")
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("first")
	source := fileSource{path: path}
	first, err := source.Get(context.Background())
	if err != nil || first.AccessKeyID != "first" || first.Expiration.Before(time.Now()) {
		t.Fatalf("first credentials: %+v, %v", first, err)
	}
	write("second")
	second, err := source.Get(context.Background())
	if err != nil || second.AccessKeyID != "second" {
		t.Fatalf("updated credentials: %+v, %v", second, err)
	}
}

func TestZTSSourceRequestsAWSRole(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/zts/v1/domain/awsshowcase/role/showcaserole/creds" {
			t.Errorf("unexpected ZTS path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"accessKeyId":"assumed-key","secretAccessKey":"assumed-secret","sessionToken":"assumed-token","expiration":"2030-01-01T00:00:00.000Z"}`))
	}))
	defer server.Close()
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	source, err := newZTSSource(config{
		ztsEndpoint: server.URL + "/zts/v1",
		domain:      "awsshowcase",
		role:        "showcaserole",
		caFile:      caFile,
	})
	if err != nil {
		t.Fatal(err)
	}
	creds, err := source.Get(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if creds.AccessKeyID != "assumed-key" || creds.SecretAccessKey != "assumed-secret" || creds.SessionToken != "assumed-token" {
		t.Fatalf("unexpected ZTS credentials: %+v", creds)
	}
}
