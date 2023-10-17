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
	"errors"
	"fmt"
	"os"
)

// NewTLSConfig returns a *tls.Config with provided certificate and key. If ca != "", client authentication is enabled.
func NewTLSConfig(ca, cert, key string) (*tls.Config, error) {
	t := &tls.Config{
		MinVersion: tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{
			tls.CurveP521,
			tls.CurveP384,
			tls.CurveP256,
			tls.X25519,
		}, // TODO: copy from sidecar, need further review
		SessionTicketsDisabled: true, // TODO: copy from sidecar, need further review
		ClientAuth:             tls.NoClientCert,
	}

	// server TLS certificate and key
	crt, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		return nil, fmt.Errorf("Cannot load X509 key pair cert [%q], key [%q]: %w", cert, key, err)
	}
	t.Certificates = make([]tls.Certificate, 1)
	t.Certificates[0] = crt

	// optional CA certificate for client
	if ca != "" {
		pool, err := NewX509CertPool(ca)
		if err != nil {
			return nil, fmt.Errorf("Cannot load CA cert [%q]: %w", ca, err)
		}
		t.ClientCAs = pool
		t.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return t, nil
}

// NewX509CertPool returns a certificate pool with the system CAs and the extra CA specified.
func NewX509CertPool(extraCA string) (pool *x509.CertPool, err error) {
	caByte, err := os.ReadFile(extraCA)
	if err != nil {
		return nil, err
	}

	// load system CAs
	pool, err = x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}

	if !pool.AppendCertsFromPEM(caByte) {
		return nil, errors.New("Cannot append CA certificate to pool")
	}
	return pool, err
}
