package imds

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/AthenZ/k8s-athenz-sia/v3/pkg/config"
	"github.com/AthenZ/k8s-athenz-sia/v3/pkg/util"
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
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/zts/v1/domain/awsshowcase/role/showcaserole/creds" {
			t.Errorf("unexpected ZTS path: %s", r.URL.Path)
		}
		if len(r.TLS.PeerCertificates) != 1 {
			t.Errorf("ZTS request has no client certificate")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"accessKeyId":"assumed-key","secretAccessKey":"assumed-secret","sessionToken":"assumed-token","expiration":"2030-01-01T00:00:00.000Z"}`))
	}))
	server.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert}
	server.StartTLS()
	defer server.Close()
	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(server.TLS.Certificates[0].PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(dir, "client.key")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	certFile := filepath.Join(dir, "client.cert")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	reloader, err := util.NewCertReloader(util.ReloadConfig{
		CertFiles: []string{certFile}, KeyFiles: []string{keyFile},
		Logger: func(string, ...interface{}) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reloader.Close() })
	source, err := newZTSSource(&config.IdentityConfig{
		Endpoint:     server.URL + "/zts/v1",
		ServerCACert: caFile,
		Reloader:     reloader,
		IMDSServer: config.IMDSServerConfig{
			Domain: "awsshowcase",
			Role:   "showcaserole",
		},
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
