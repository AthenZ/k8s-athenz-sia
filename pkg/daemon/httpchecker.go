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

package daemon

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/AthenZ/k8s-athenz-sia/v3/pkg/config"
	"github.com/AthenZ/k8s-athenz-sia/v3/third_party/log"
	"github.com/cenkalti/backoff"
)

func serverRequest(client *http.Client, url string) error {
	get := func() error {
		resp, err := client.Get(url)
		if err == nil {
			resp.Body.Close()
			log.Debugf("Server started at %s", url)
		}
		return err
	}

	getExponentialBackoff := func() backoff.BackOff {
		b := backoff.NewExponentialBackOff()
		b.InitialInterval = 5 * time.Second
		b.Multiplier = 2
		b.MaxElapsedTime = config.DEFAULT_MAX_ELAPSED_TIME_ON_INIT
		return b
	}

	time.Sleep(1 * time.Millisecond) // pause current goroutine to allow goroutines with http.Server.ListenAndServe() to run
	return backoff.RetryNotify(get, getExponentialBackoff(), func(err error, backoffDelay time.Duration) {
		log.Warnf("Failed to confirm the server ready with GET request: %s. Retrying in %s", err.Error(), backoffDelay)
	})
}

// WaitForServerReady waits until the HTTP server can respond to a GET request. Should NOT allow cancelling the retry as shuting down non-ready server may cause deadlock.
func WaitForServerReady(serverAddr string) error {

	t := http.DefaultTransport.(*http.Transport).Clone()
	client := &http.Client{Transport: t}

	url := "http://" + serverAddr

	return serverRequest(client, url)
}

// WaitForServerReady waits until the HTTPS server can respond to a GET request. Should NOT allow cancelling the retry as shuting down non-ready server may cause deadlock.
func WaitForServerReadyWithTLS(serverAddr string, tlsConfig config.TLS) error {
	if !tlsConfig.Use {
		return fmt.Errorf("The server attempted to perform a server check using HTTPS even though TLS was disabled.")
	}

	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig = &tls.Config{}
	t.TLSClientConfig.InsecureSkipVerify = true

	if tlsConfig.CAPath != "" {
		crt, err := tls.LoadX509KeyPair(tlsConfig.CertPath, tlsConfig.KeyPath)
		if err != nil {
			return fmt.Errorf("Cannot load X509 key pair cert [%q], key [%q]: %w", tlsConfig.CertPath, tlsConfig.KeyPath, err)
		}
		t.TLSClientConfig.Certificates = make([]tls.Certificate, 1)
		t.TLSClientConfig.Certificates[0] = crt

		caByte, err := os.ReadFile(tlsConfig.CAPath)
		if err != nil {
			return err
		}

		// load system CAs
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}

		if !pool.AppendCertsFromPEM(caByte) {
			return fmt.Errorf("Cannot append CA certificate to pool")
		}

		if err != nil {
			return fmt.Errorf("Cannot load CA cert [%q]: %w", tlsConfig.CAPath, err)
		}
		t.TLSClientConfig.ClientCAs = pool
	}

	client := &http.Client{Transport: t}

	url := "https://" + serverAddr

	return serverRequest(client, url)
}
