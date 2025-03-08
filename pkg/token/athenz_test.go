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

package token

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"os"
	"path"
	"testing"
	"time"

	"github.com/AthenZ/athenz/clients/go/zts"
	"github.com/AthenZ/k8s-athenz-sia/v3/pkg/config"
	"github.com/AthenZ/k8s-athenz-sia/v3/pkg/util"
	"github.com/AthenZ/k8s-athenz-sia/v3/third_party/log"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/ghttp"
)

func Test_newZTSClient(t *testing.T) {
	type args struct {
		reloader     *util.CertReloader
		serverCAPath string
		endpoint     string
	}
	type test struct {
		name        string
		args        args
		wantNil     bool
		wantErr     bool
		before      func(*WithT, args) args
		after       func()
		assertExtra func(*WithT, *zts.ZTSClient)
	}
	tests := []test{
		{
			name: "Non-exist server CA",
			args: args{
				serverCAPath: "testdata/non-exist",
			},
			wantNil: true,
			wantErr: true,
		},
		func(t *testing.T) test {
			server := ghttp.NewTLSServer()
			// save server cert to tempDir
			b := bytes.Buffer{}
			err := pem.Encode(&b, &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: server.HTTPTestServer.Certificate().Raw,
			})
			if err != nil {
				t.Fatalf("unable to encode test server certificate: %s", err.Error())
				return test{}
			}
			serverCertPath := path.Join(t.TempDir(), "server.crt")
			err = os.WriteFile(serverCertPath, b.Bytes(), 0744)
			if err != nil {
				t.Fatalf("unable to write test server certificate to file: %s", err.Error())
				return test{}
			}
			// response
			responseBody := zts.Status{
				Code:    200,
				Message: "OK",
			}

			return test{
				name:    "Success with serverCAPath set",
				args:    args{},
				wantNil: false,
				wantErr: false,
				before: func(g *WithT, a args) args {
					gh := ghttp.NewGHTTPWithGomega(g)
					// set server handlers
					server.AppendHandlers(ghttp.CombineHandlers(
						gh.VerifyRequest("GET", "/status"),
						gh.VerifyHeaderKV("User-Agent", config.USER_AGENT),
						gh.RespondWithJSONEncoded(http.StatusOK, responseBody),
					))
					// set args
					a.serverCAPath = serverCertPath
					a.endpoint = server.URL()
					return a
				},
				after: func() {
					server.Close()
				},
				assertExtra: func(g *WithT, ztsClient *zts.ZTSClient) {
					gotStatus, err := ztsClient.GetStatus()
					g.Expect(err).ToNot(HaveOccurred())
					g.Expect(gotStatus).To(Equal(&responseBody))
				},
			}
		}(t),
		func(t *testing.T) test {
			server := ghttp.NewTLSServer()
			// cert reloader
			certReloader, err := util.NewCertReloader(util.ReloadConfig{
				CertFile:     "testdata/valid_cert.pem",
				KeyFile:      "testdata/valid_key.pem",
				Logger:       t.Logf,
				PollInterval: time.Second,
			})
			if err != nil {
				t.Fatalf("unable to create cert reloader: %s", err.Error())
				return test{}
			}
			// response
			responseBody := zts.Status{
				Code:    200,
				Message: "OK",
			}

			return test{
				name:    "Success with client cert in cert reloader",
				args:    args{},
				wantNil: false,
				wantErr: false,
				before: func(g *WithT, a args) args {
					gh := ghttp.NewGHTTPWithGomega(g)
					// set server TLS
					_, clientCertPEM, _ := certReloader.GetLatestKeyAndCert()
					server.HTTPTestServer.TLS.ClientCAs = x509.NewCertPool()
					server.HTTPTestServer.TLS.ClientCAs.AppendCertsFromPEM(clientCertPEM)
					server.HTTPTestServer.TLS.ClientAuth = tls.RequireAndVerifyClientCert
					// set server handlers
					server.AppendHandlers(ghttp.CombineHandlers(
						gh.VerifyRequest("GET", "/status"),
						gh.VerifyHeaderKV("User-Agent", config.USER_AGENT),
						gh.RespondWithJSONEncoded(http.StatusOK, responseBody),
						func(w http.ResponseWriter, r *http.Request) {
							g.Expect(r.TLS.PeerCertificates[0].Subject.String()).To(Equal("CN=athenz.local,OU=AV-Security,O=AV Corp LLC,C=US"), "client cert subject does not match")
						},
					))
					// set args
					a.endpoint = server.URL()
					a.reloader = certReloader
					return a
				},
				after: func() {
					server.Close()
				},
				assertExtra: func(g *WithT, ztsClient *zts.ZTSClient) {
					ztsClient.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify = true
					gotStatus, err := ztsClient.GetStatus()
					g.Expect(err).ToNot(HaveOccurred())
					g.Expect(gotStatus).To(Equal(&responseBody))
				},
			}
		}(t),
	}

	log.InitLogger("", "DEBUG", false) // init logger
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t) // wraps with gomega
			// test method
			if tt.before != nil {
				tt.args = tt.before(g, tt.args)
			}
			got, err := newZTSClient(tt.args.reloader, tt.args.serverCAPath, tt.args.endpoint)
			if tt.after != nil {
				defer tt.after()
			}
			// assert result
			if tt.wantErr {
				g.Expect(err).To(HaveOccurred())
			} else {
				g.Expect(err).ToNot(HaveOccurred())
			}
			if tt.wantNil {
				g.Expect(got).To(BeNil())
				return
			}
			if tt.assertExtra != nil {
				tt.assertExtra(g, got)
			}
		})
	}
}

func Test_fetchAccessToken(t *testing.T) {
	type args struct {
		ztsClient *zts.ZTSClient
		t         CacheKey
		saService string
	}
	type test struct {
		name    string
		args    args
		want    *AccessToken
		wantErr bool
		before  func(*WithT, args) args
		after   func()
	}
	tests := []test{
		func(t *testing.T) test {
			server := ghttp.NewServer()
			server.SetAllowUnhandledRequests(true)
			server.SetUnhandledRequestStatusCode(http.StatusNotImplemented)
			client := zts.ZTSClient{
				URL:       server.URL(),
				Transport: server.HTTPTestServer.Client().Transport,
			}

			return test{
				name: "Fail with response 401",
				args: args{
					ztsClient: &client,
					t: CacheKey{
						Domain:            "test-domain",
						Role:              "test-role",
						ProxyForPrincipal: "",
						MaxExpiry:         3600,
						MinExpiry:         3600,
					},
					saService: "",
				},
				want:    nil,
				wantErr: true,
				before: func(g *WithT, a args) args {
					gh := ghttp.NewGHTTPWithGomega(g)
					// set server handlers
					server.AppendHandlers(ghttp.CombineHandlers(
						gh.VerifyRequest("POST", "/oauth2/token"),
						gh.RespondWith(http.StatusUnauthorized, ""),
					))

					return a
				},
				after: func() {
					server.Close()
				},
			}
		}(t),
		func(t *testing.T) test {
			server := ghttp.NewServer()
			server.SetAllowUnhandledRequests(true)
			server.SetUnhandledRequestStatusCode(http.StatusNotImplemented)
			client := zts.ZTSClient{
				URL:       server.URL(),
				Transport: server.HTTPTestServer.Client().Transport,
			}
			// response
			expiresIn := int32(3600)
			responseBody := zts.AccessTokenResponse{
				Access_token: "invalid.header.payload.signature",
				Token_type:   "Bearer",
				Expires_in:   &expiresIn,
				Scope:        "test-scope",
			}

			return test{
				name: "Fail with invalid JWT",
				args: args{
					ztsClient: &client,
					t: CacheKey{
						Domain:            "test-domain",
						Role:              "test-role",
						ProxyForPrincipal: "",
						MaxExpiry:         3600,
						MinExpiry:         3600,
					},
					saService: "",
				},
				want:    nil,
				wantErr: true,
				before: func(g *WithT, a args) args {
					gh := ghttp.NewGHTTPWithGomega(g)
					// set server handlers
					server.AppendHandlers(ghttp.CombineHandlers(
						gh.VerifyRequest("POST", "/oauth2/token"),
						gh.RespondWithJSONEncoded(http.StatusOK, responseBody),
					))

					return a
				},
				after: func() {
					server.Close()
				},
			}
		}(t),
		func(t *testing.T) test {
			server := ghttp.NewServer()
			server.SetAllowUnhandledRequests(true)
			server.SetUnhandledRequestStatusCode(http.StatusNotImplemented)
			client := zts.ZTSClient{
				URL:       server.URL(),
				Transport: server.HTTPTestServer.Client().Transport,
			}
			// response
			expiresIn := int32(3600)
			responseBody := zts.AccessTokenResponse{
				// token details: /pkg/token/testdata/access_token.valid.md
				Access_token: "eyJ0eXAiOiJhdCtqd3QiLCJhbGciOiJFUzI1NiIsImtpZCI6Ijc3ZTFiOTBhNDRlN2UwZTQ0ZGJkZjY4NDNkNTJiZWQ1In0.eyJpc3MiOiJpc3N1ZXIiLCJhdWQiOiJhdWRpZW5jZSIsInN1YiI6IjViZTg2MzU5MDczYzQzNGJhZDJkYTM5MzIyMjJkYWJlIiwiY2xpZW50X2lkIjoiY2xpZW50X2FwcCIsImV4cCI6MTc0MTQxNjM5NywiaWF0IjoxNzQxNDEyNzk3LCJqdGkiOiJjZjRkYWYzZThlYjY5MTEwYzZhNWYyNWFkODZmZmVjZSIsInNjb3BlIjoicmVhZCB3cml0ZSBkZWxldGUifQ.c6KmZ7E7ESk_wAEgFG-JDkQXzPJluNjTwo2XMhR5YBgd2EXEKKFBR_gORQNBv1HgVg8dB05qG9N-kyUI__tG1A",
				Token_type:   "Bearer",
				Expires_in:   &expiresIn,
				Scope:        "read write delete",
			}

			return test{
				name: "Succeed with valid JWT",
				args: args{
					ztsClient: &client,
					t: CacheKey{
						Domain:            "test-domain",
						Role:              "test-role",
						ProxyForPrincipal: "",
						MaxExpiry:         3600,
						MinExpiry:         3600,
					},
					saService: "",
				},
				want: &AccessToken{
					domain: "test-domain",
					role:   "test-role",
					scope:  "read write delete",
					expiry: 1741416397,
					raw:    responseBody.Access_token,
				},
				wantErr: false,
				before: func(g *WithT, a args) args {
					gh := ghttp.NewGHTTPWithGomega(g)
					// set server handlers
					server.AppendHandlers(ghttp.CombineHandlers(
						gh.VerifyRequest("POST", "/oauth2/token"),
						gh.RespondWithJSONEncoded(http.StatusOK, responseBody),
					))

					return a
				},
				after: func() {
					server.Close()
				},
			}
		}(t),
		func(t *testing.T) test {
			server := ghttp.NewServer()
			server.SetAllowUnhandledRequests(true)
			server.SetUnhandledRequestStatusCode(http.StatusNotImplemented)
			client := zts.ZTSClient{
				URL:       server.URL(),
				Transport: server.HTTPTestServer.Client().Transport,
			}
			// response
			expiresIn := int32(3600)
			responseBody := zts.AccessTokenResponse{
				// token details: /pkg/token/testdata/access_token.valid.md
				Access_token: "eyJ0eXAiOiJhdCtqd3QiLCJhbGciOiJFUzI1NiIsImtpZCI6Ijc3ZTFiOTBhNDRlN2UwZTQ0ZGJkZjY4NDNkNTJiZWQ1In0.eyJpc3MiOiJpc3N1ZXIiLCJhdWQiOiJhdWRpZW5jZSIsInN1YiI6IjViZTg2MzU5MDczYzQzNGJhZDJkYTM5MzIyMjJkYWJlIiwiY2xpZW50X2lkIjoiY2xpZW50X2FwcCIsImV4cCI6MTc0MTQxNjM5NywiaWF0IjoxNzQxNDEyNzk3LCJqdGkiOiJjZjRkYWYzZThlYjY5MTEwYzZhNWYyNWFkODZmZmVjZSIsInNjb3BlIjoicmVhZCB3cml0ZSBkZWxldGUifQ.c6KmZ7E7ESk_wAEgFG-JDkQXzPJluNjTwo2XMhR5YBgd2EXEKKFBR_gORQNBv1HgVg8dB05qG9N-kyUI__tG1A",
				Token_type:   "Bearer",
				Expires_in:   &expiresIn,
				Scope:        "read write delete",
			}

			return test{
				name: "Succeed with extra request parameters",
				args: args{
					ztsClient: &client,
					t: CacheKey{
						Domain: "test-domain",
						// MaxExpiry: 3600,
						// MinExpiry: 3600,
						// Role: "test-role",
						ProxyForPrincipal: "proxy-for-principal",
					},
					saService: "sa-service",
				},
				want: &AccessToken{
					domain: "test-domain",
					role:   "",
					scope:  "read write delete",
					expiry: 1741416397,
					raw:    responseBody.Access_token,
				},
				wantErr: false,
				before: func(g *WithT, a args) args {
					gh := ghttp.NewGHTTPWithGomega(g)
					// set server handlers
					server.AppendHandlers(ghttp.CombineHandlers(
						gh.VerifyRequest("POST", "/oauth2/token"),
						gh.VerifyFormKV("grant_type", "client_credentials"),
						gh.VerifyFormKV("scope", "test-domain:domain openid test-domain:service.sa-service"),
						gh.VerifyFormKV("proxy_for_principal", "proxy-for-principal"),
						gh.RespondWithJSONEncoded(http.StatusOK, responseBody),
					))

					return a
				},
				after: func() {
					server.Close()
				},
			}
		}(t),
	}

	log.InitLogger("", "DEBUG", false) // init logger
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			g := NewWithT(t) // wraps with gomega
			// test method
			if tt.before != nil {
				tt.args = tt.before(g, tt.args)
			}
			got, err := fetchAccessToken(tt.args.ztsClient, tt.args.t, tt.args.saService)
			if tt.after != nil {
				defer tt.after()
			}
			// assert result
			if tt.wantErr {
				g.Expect(err).To(HaveOccurred())
			} else {
				g.Expect(err).ToNot(HaveOccurred())
			}
			if tt.want == nil {
				g.Expect(got).To(BeNil())
			}
			g.Expect(got).To(Equal(tt.want))
		})
	}
}

func Test_fetchRoleToken(t *testing.T) {
	type args struct {
		ztsClient *zts.ZTSClient
		t         CacheKey
	}
	type test struct {
		name    string
		args    args
		want    *RoleToken
		wantErr bool
		before  func(*WithT, args) args
		after   func()
	}
	tests := []test{
		func(t *testing.T) test {
			server := ghttp.NewServer()
			server.SetAllowUnhandledRequests(true)
			server.SetUnhandledRequestStatusCode(http.StatusNotImplemented)
			client := zts.ZTSClient{
				URL:       server.URL(),
				Transport: server.HTTPTestServer.Client().Transport,
			}

			return test{
				name: "Fail with response 401",
				args: args{
					ztsClient: &client,
					t: CacheKey{
						Domain:    "test-domain",
						Role:      "test-role",
						MinExpiry: 3600,
					},
				},
				want:    nil,
				wantErr: true,
				before: func(g *WithT, a args) args {
					gh := ghttp.NewGHTTPWithGomega(g)
					// set server handlers
					server.AppendHandlers(ghttp.CombineHandlers(
						gh.VerifyRequest("GET", "/domain/test-domain/token"),
						gh.RespondWith(http.StatusUnauthorized, ""),
					))

					return a
				},
				after: func() {
					server.Close()
				},
			}
		}(t),
		func(t *testing.T) test {
			server := ghttp.NewServer()
			server.SetAllowUnhandledRequests(true)
			server.SetUnhandledRequestStatusCode(http.StatusNotImplemented)
			client := zts.ZTSClient{
				URL:       server.URL(),
				Transport: server.HTTPTestServer.Client().Transport,
			}
			// response
			responseBody := zts.RoleToken{}

			return test{
				name: "Fail with empty response token",
				args: args{
					ztsClient: &client,
					t: CacheKey{
						Domain:    "test-domain",
						Role:      "test-role",
						MinExpiry: 3600,
					},
				},
				want:    nil,
				wantErr: true,
				before: func(g *WithT, a args) args {
					gh := ghttp.NewGHTTPWithGomega(g)
					// set server handlers
					server.AppendHandlers(ghttp.CombineHandlers(
						gh.VerifyRequest("GET", "/domain/test-domain/token"),
						gh.RespondWithJSONEncoded(http.StatusOK, responseBody),
					))

					return a
				},
				after: func() {
					server.Close()
				},
			}
		}(t),
		func(t *testing.T) test {
			server := ghttp.NewServer()
			server.SetAllowUnhandledRequests(true)
			server.SetUnhandledRequestStatusCode(http.StatusNotImplemented)
			client := zts.ZTSClient{
				URL:       server.URL(),
				Transport: server.HTTPTestServer.Client().Transport,
			}
			// response
			responseBody := zts.RoleToken{
				Token:      "test-role-token",
				ExpiryTime: time.Now().Unix(),
			}

			return test{
				name: "Success",
				args: args{
					ztsClient: &client,
					t: CacheKey{
						Domain:    "test-domain",
						Role:      "test-role",
						MinExpiry: 3600,
						MaxExpiry: 3600,
					},
				},
				want: &RoleToken{
					domain: "test-domain",
					role:   "test-role",
					raw:    "test-role-token",
					expiry: responseBody.ExpiryTime,
				},
				wantErr: false,
				before: func(g *WithT, a args) args {
					gh := ghttp.NewGHTTPWithGomega(g)
					// set server handlers
					server.AppendHandlers(ghttp.CombineHandlers(
						// max_expiry=3600 should be added
						gh.VerifyRequest("GET", "/domain/test-domain/token", "role=test-role&minExpiryTime=3600"),
						gh.RespondWithJSONEncoded(http.StatusOK, responseBody),
					))

					return a
				},
				after: func() {
					server.Close()
				},
			}
		}(t),
	}

	log.InitLogger("", "DEBUG", false) // init logger
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t) // wraps with gomega
			// test method
			if tt.before != nil {
				tt.args = tt.before(g, tt.args)
			}
			got, err := fetchRoleToken(tt.args.ztsClient, tt.args.t)
			if tt.after != nil {
				defer tt.after()
			}
			// assert result
			if tt.wantErr {
				g.Expect(err).To(HaveOccurred())
			} else {
				g.Expect(err).ToNot(HaveOccurred())
			}
			if tt.want == nil {
				g.Expect(got).To(BeNil())
			}
			g.Expect(got).To(Equal(tt.want))
		})
	}
}
