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

package util

import (
	"crypto/tls"
	"io"
	"os"
	"path"
	"testing"
	"time"

	. "github.com/onsi/gomega"
)

func TestNewCertReloader(t *testing.T) {
	type args struct {
		config ReloadConfig
	}
	tests := []struct {
		name        string
		args        args
		wantNil     bool
		wantErr     bool
		before      func(*testing.T, args) args
		assertExtra func(*WithT, *CertReloader)
	}{
		{
			name: "Test NewCertReloader error in init mode",
			args: args{
				config: ReloadConfig{
					CertFile: "testdata/non-exist",
					KeyFile:  "testdata/non-exist",
					Init:     true,
				},
			},
			wantNil: false,
			wantErr: true,
		},
		{
			name: "Test NewCertReloader error in non-init mode",
			args: args{
				config: ReloadConfig{
					CertFile: "testdata/non-exist",
					KeyFile:  "testdata/non-exist",
					Init:     false,
				},
			},
			wantNil: true,
			wantErr: true,
		},
		{
			name: "Test NewCertReloader success",
			args: args{
				config: ReloadConfig{
					CertFile:        "testdata/dummy_client.crt",
					KeyFile:         "testdata/dummy_client.key",
					ProviderService: "provider-service", // disable refresh
				},
			},
			wantNil: false,
			wantErr: false,
			assertExtra: func(g *WithT, got *CertReloader) {
				key, cert, err := got.GetLatestKeyAndCert()
				g.Expect(err).ToNot(HaveOccurred())

				wantKey, err := os.ReadFile("testdata/dummy_client.key")
				if err != nil {
					g.Fail("cannot read expected key file")
					return
				}
				wantCert, err := os.ReadFile("testdata/dummy_client.crt")
				if err != nil {
					g.Fail("cannot read expected cert file")
					return
				}

				g.Expect(key).To(Equal(wantKey), "loaded key to be equal to testdata/dummy_client.key")
				g.Expect(cert).To(Equal(wantCert), "loaded cert to be equal to testdata/dummy_client.crt")
			},
		},
		{
			name: "Test NewCertReloader refresh",
			args: args{
				config: ReloadConfig{
					CertFile:        "testdata/dummy_client.crt", // copy to TempDir in before func
					KeyFile:         "testdata/dummy_client.key", // copy to TempDir in before func
					ProviderService: "",                          // enable refresh
				},
			},
			wantNil: false,
			wantErr: false,
			before: func(t *testing.T, a args) args {
				tmpPath := t.TempDir()
				tmpCertPath := path.Join(tmpPath, "/dummy_client.crt")
				tmpKeyPath := path.Join(tmpPath, "/dummy_client.key")

				copyFile := func(srcPath, dstPath string) error {
					src, err := os.Open(srcPath)
					if err != nil {
						return err
					}
					dst, err := os.Create(dstPath)
					if err != nil {
						return err
					}

					_, err = io.Copy(dst, src)
					if err != nil {
						return err
					}
					return nil
				}

				// update cert and key file after 1.5s
				go func() {
					time.Sleep(1500 * time.Millisecond)

					copyFile("testdata/dummy_server.crt", tmpCertPath)
					copyFile("testdata/dummy_server.key", tmpKeyPath)
				}()

				copyFile(a.config.CertFile, tmpCertPath)
				copyFile(a.config.KeyFile, tmpKeyPath)
				a.config.CertFile = tmpCertPath
				a.config.KeyFile = tmpKeyPath

				return a
			},
			assertExtra: func(g *WithT, got *CertReloader) {
				key, cert, err := got.GetLatestKeyAndCert()
				g.Expect(err).ToNot(HaveOccurred())

				wantKey, err := os.ReadFile("testdata/dummy_client.key")
				if err != nil {
					g.Fail("cannot read expected key file")
					return
				}
				wantCert, err := os.ReadFile("testdata/dummy_client.crt")
				if err != nil {
					g.Fail("cannot read expected cert file")
					return
				}

				g.Expect(key).To(Equal(wantKey), "loaded key to be equal to testdata/dummy_client.key")
				g.Expect(cert).To(Equal(wantCert), "loaded cert to be equal to testdata/dummy_client.crt")

				// assert cert and key refreshed
				wantRefreshedCert, err := tls.LoadX509KeyPair("testdata/dummy_server.crt", "testdata/dummy_server.key")
				if err != nil {
					g.Fail("cannot read expected cert file for refresh")
					return
				}
				g.Eventually(got.GetLatestCertificate).WithTimeout(3*time.Second).Should(Equal(&wantRefreshedCert), "refreshed cert to be equal to testdata/dummy_server.crt")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t) // wraps with gomega
			// test method
			if tt.before != nil {
				tt.args = tt.before(t, tt.args)
			}
			got, err := NewCertReloader(tt.args.config)
			// assert result
			if tt.wantErr {
				g.Expect(err).To(HaveOccurred())
			} else {
				g.Expect(err).ToNot(HaveOccurred())
			}
			if tt.wantNil {
				g.Expect(got).To(BeNil())
			} else {
				g.Expect(got).ToNot(BeNil())
			}
			if tt.assertExtra != nil {
				tt.assertExtra(g, got)
			}
		})
	}
}

func TestCertReloader_UpdateCertificate(t *testing.T) {
	type fields struct {
		// l            sync.RWMutex // auto created
		certFile     string
		keyFile      string
		cert         *tls.Certificate
		certPEM      []byte
		keyPEM       []byte
		mtime        time.Time
		pollInterval time.Duration
		logger       LogFn
		// stop         chan struct{} // auto created
	}
	type args struct {
		certPEM []byte
		keyPEM  []byte
	}
	type test struct {
		name        string
		fields      fields
		args        args
		wantErr     bool
		wantCert    *tls.Certificate
		wantCertPem []byte
		wantKeyPem  []byte
	}
	tests := []test{
		func(t *testing.T) test {
			// before update
			certPath := "testdata/dummy_client.crt"
			keyPath := "testdata/dummy_client.key"
			cert, err := tls.LoadX509KeyPair(certPath, keyPath)
			if err != nil {
				t.Fatalf("unable to load cert from %s,%s", certPath, keyPath)
				return test{}
			}
			certPEM, err := os.ReadFile(certPath)
			if err != nil {
				t.Fatalf("unable to load cert from %s", certPath)
				return test{}
			}
			keyPEM, err := os.ReadFile(keyPath)
			if err != nil {
				t.Fatalf("unable to load key from %s", keyPath)
				return test{}
			}
			// mismatching cert-key pair for update error
			updatedKeyPath := "testdata/dummy_server.key"
			updatedKeyPEM, err := os.ReadFile(updatedKeyPath)
			if err != nil {
				t.Fatalf("unable to load key from %s", keyPath)
				return test{}
			}

			return test{
				name: "Test UpdateCertificate fail",
				fields: fields{
					certFile:     "testdata/dummy_client.crt",
					keyFile:      "testdata/dummy_client.key",
					cert:         &cert,
					certPEM:      certPEM,
					keyPEM:       keyPEM,
					mtime:        time.Now(),
					pollInterval: 1 * time.Second,
					logger:       t.Logf,
				},
				args: args{
					certPEM: certPEM,
					keyPEM:  updatedKeyPEM,
				},
				wantErr:     true,
				wantCert:    &cert,
				wantCertPem: certPEM,
				wantKeyPem:  keyPEM,
			}
		}(t),
		func(t *testing.T) test {
			// before update
			certPath := "testdata/dummy_client.crt"
			keyPath := "testdata/dummy_client.key"
			cert, err := tls.LoadX509KeyPair(certPath, keyPath)
			if err != nil {
				t.Fatalf("unable to load cert from %s,%s", certPath, keyPath)
				return test{}
			}
			certPEM, err := os.ReadFile(certPath)
			if err != nil {
				t.Fatalf("unable to load cert from %s", certPath)
				return test{}
			}
			keyPEM, err := os.ReadFile(keyPath)
			if err != nil {
				t.Fatalf("unable to load key from %s", keyPath)
				return test{}
			}
			// after update
			updatedCertPath := "testdata/dummy_server.crt"
			updatedKeyPath := "testdata/dummy_server.key"
			updatedCert, err := tls.LoadX509KeyPair(updatedCertPath, updatedKeyPath)
			if err != nil {
				t.Fatalf("unable to load cert from %s,%s", updatedCertPath, updatedKeyPath)
				return test{}
			}
			updatedCertPEM, err := os.ReadFile(updatedCertPath)
			if err != nil {
				t.Fatalf("unable to load cert from %s", updatedCertPath)
				return test{}
			}
			updatedKeyPEM, err := os.ReadFile(updatedKeyPath)
			if err != nil {
				t.Fatalf("unable to load key from %s", keyPath)
				return test{}
			}

			return test{
				name: "Test UpdateCertificate success",
				fields: fields{
					certFile:     "testdata/dummy_client.crt",
					keyFile:      "testdata/dummy_client.key",
					cert:         &cert,
					certPEM:      certPEM,
					keyPEM:       keyPEM,
					mtime:        time.Now(),
					pollInterval: 1 * time.Second,
					logger:       t.Logf,
				},
				args: args{
					certPEM: updatedCertPEM,
					keyPEM:  updatedKeyPEM,
				},
				wantErr:     false,
				wantCert:    &updatedCert,
				wantCertPem: updatedCertPEM,
				wantKeyPem:  updatedKeyPEM,
			}
		}(t),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t) // wraps with gomega
			// test method
			w := &CertReloader{
				certFile:     tt.fields.certFile,
				keyFile:      tt.fields.keyFile,
				cert:         tt.fields.cert,
				certPEM:      tt.fields.certPEM,
				keyPEM:       tt.fields.keyPEM,
				mtime:        tt.fields.mtime,
				pollInterval: tt.fields.pollInterval,
				logger:       tt.fields.logger,
			}
			err := w.UpdateCertificate(tt.args.certPEM, tt.args.keyPEM)
			// assert result
			if tt.wantErr {
				g.Expect(err).To(HaveOccurred())
			} else {
				g.Expect(err).ToNot(HaveOccurred())
			}
			g.Expect(w.cert).To(Equal(tt.wantCert))
			g.Expect(w.certPEM).To(Equal(tt.wantCertPem))
			g.Expect(w.keyPEM).To(Equal(tt.wantKeyPem))
		})
	}
}
