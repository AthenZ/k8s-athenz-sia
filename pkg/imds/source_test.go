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
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AthenZ/athenz/clients/go/zts"
	"github.com/AthenZ/k8s-athenz-sia/v3/pkg/config"
	"github.com/AthenZ/k8s-athenz-sia/v3/pkg/util"
)

func TestFileSourceReadsUpdatedCredentials(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials")
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

func TestFileSourceUsesTemporaryCredentialsExpiration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials")
	expiration := time.Now().UTC().Add(30 * time.Minute).Truncate(time.Second)
	data := []byte("[default]\naws_access_key_id=key\naws_secret_access_key=secret\naws_session_token=token\nexpiration=" + expiration.Format(time.RFC3339) + "\n")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	creds, err := (fileSource{path: path}).Get(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if creds.SessionToken != "token" || !creds.Expiration.Equal(expiration) {
		t.Fatalf("temporary credentials: %+v", creds)
	}
}

func TestFileSourceRejectsUnavailableCredentials(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials")
	if _, err := (fileSource{path: path}).Get(context.Background()); !os.IsNotExist(err) {
		t.Fatalf("missing file: %v", err)
	}

	for _, tc := range []struct {
		name, contents, want string
	}{
		{"other profile", "[other]\naws_access_key_id=key\naws_secret_access_key=secret\n", "no access key"},
		{"missing secret", "[default]\naws_access_key_id=key\n", "no access key"},
		{"invalid expiration", "[default]\naws_access_key_id=key\naws_secret_access_key=secret\nexpiration=invalid\n", "invalid AWS credentials expiration"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(tc.contents), 0600); err != nil {
				t.Fatal(err)
			}
			_, err := (fileSource{path: path}).Get(context.Background())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q error, got %v", tc.want, err)
			}
		})
	}
}

func TestZTSSourceRejectsInvalidCA(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ca.pem")
	if _, err := newZTSSource(&config.IdentityConfig{ServerCACert: path}); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing CA file: %v", err)
	}
	if err := os.WriteFile(path, []byte("not a certificate"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := newZTSSource(&config.IdentityConfig{ServerCACert: path}); err == nil ||
		!strings.Contains(err.Error(), "contains no certificates") {
		t.Fatalf("invalid CA: %v", err)
	}
}

func TestZTSSourceRejectsUnavailableCredentials(t *testing.T) {
	for _, tc := range []struct {
		name, response string
		status         int
	}{
		{"denied", `{"code":403,"message":"denied"}`, http.StatusForbidden},
		{"empty response", `null`, http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Get("durationSeconds") != "900" {
					t.Errorf("durationSeconds = %q", r.URL.Query().Get("durationSeconds"))
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.response))
			}))
			defer server.Close()
			source := ztsSource{
				client: zts.NewClient(server.URL+"/zts/v1", nil),
				domain: "awsshowcase", role: "showcaserole", duration: 900,
			}
			if _, err := source.Get(context.Background()); err == nil {
				t.Fatal("expected ZTS credentials error")
			}
		})
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
