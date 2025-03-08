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
	"crypto/tls"
	"crypto/x509"
	"os"
	"reflect"
	"testing"

	. "github.com/onsi/gomega"
)

func TestNewTLSConfig(t *testing.T) {
	type args struct {
		ca   string
		cert string
		key  string
	}
	type test struct {
		name    string
		args    args
		want    *tls.Config
		wantErr bool
	}
	tests := []test{
		func(t *testing.T) test {
			certPath := "testdata/expired_cert.pem"
			keyPath := "testdata/expired_key.pem"
			cert, err := tls.LoadX509KeyPair(certPath, keyPath)
			if err != nil {
				t.Fatalf("unable to load cert from %s,%s", certPath, keyPath)
				return test{}
			}

			return test{
				name: "Valid cert and key without CA",
				args: args{
					ca:   "",
					cert: "testdata/expired_cert.pem",
					key:  "testdata/expired_key.pem",
				},
				want: &tls.Config{
					MinVersion: tls.VersionTLS12,
					CurvePreferences: []tls.CurveID{
						tls.CurveP521,
						tls.CurveP384,
						tls.CurveP256,
						tls.X25519,
					},
					SessionTicketsDisabled: true,
					ClientAuth:             tls.NoClientCert,
					Certificates:           []tls.Certificate{cert},
				},
				wantErr: false,
			}
		}(t),
		func(t *testing.T) test {
			caPath := "testdata/expired_ca.pem"
			certPath := "testdata/expired_cert.pem"
			keyPath := "testdata/expired_key.pem"
			cert, err := tls.LoadX509KeyPair(certPath, keyPath)
			if err != nil {
				t.Fatalf("unable to load cert from %s,%s", certPath, keyPath)
				return test{}
			}
			// CA
			caByte, err := os.ReadFile(caPath)
			if err != nil {
				t.Fatalf("unable to CA cert from %s", caPath)
				return test{}
			}
			pool, err := x509.SystemCertPool()
			if err != nil {
				t.Fatal("unable to load system CA")
				return test{}
			}
			if !pool.AppendCertsFromPEM(caByte) {
				t.Fatal("unable to append CA to pool")
				return test{}
			}

			return test{
				name: "Valid cert, key and CA",
				args: args{
					ca:   "testdata/expired_ca.pem",
					cert: "testdata/expired_cert.pem",
					key:  "testdata/expired_key.pem",
				},
				want: &tls.Config{
					MinVersion: tls.VersionTLS12,
					CurvePreferences: []tls.CurveID{
						tls.CurveP521,
						tls.CurveP384,
						tls.CurveP256,
						tls.X25519,
					},
					SessionTicketsDisabled: true,
					Certificates:           []tls.Certificate{cert},
					ClientCAs:              pool,
					ClientAuth:             tls.RequireAndVerifyClientCert,
				},
				wantErr: false,
			}
		}(t),
		{
			name: "Non-exist cert and key",
			args: args{
				ca:   "",
				cert: "testdata/non-exist",
				key:  "testdata/non-exist",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "Non-exist CA",
			args: args{
				ca:   "testdata/non-exist",
				cert: "testdata/expired_cert.pem",
				key:  "testdata/expired_key.pem",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "Invalid CA",
			args: args{
				ca:   "testdata/negative_serial_ca.pem",
				cert: "testdata/expired_cert.pem",
				key:  "testdata/expired_key.pem",
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t) // wraps with gomega
			// test method
			got, err := NewTLSConfig(tt.args.ca, tt.args.cert, tt.args.key)
			// assert result
			if tt.wantErr {
				g.Expect(err).To(HaveOccurred())
			} else {
				g.Expect(err).ToNot(HaveOccurred())
			}
			if tt.want == nil {
				g.Expect(got).To(BeNil())
				return
			}
			if tt.want.ClientCAs != nil {
				g.Expect(tt.want.ClientCAs.Equal(got.ClientCAs)).To(BeTrue())
				// exclude from next assertion
				tt.want.ClientCAs = nil
				got.ClientCAs = nil
			} else {
				g.Expect(got.ClientCAs).To(BeNil())
			}
			g.Expect(got).To(Equal(tt.want))
		})
	}
}

func TestNewX509CertPool(t *testing.T) {
	type args struct {
		extraCA string
	}
	tests := []struct {
		name     string
		args     args
		wantPool *x509.CertPool
		wantErr  bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPool, err := NewX509CertPool(tt.args.extraCA)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewX509CertPool() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotPool, tt.wantPool) {
				t.Errorf("NewX509CertPool() = %v, want %v", gotPool, tt.wantPool)
			}
		})
	}
}
