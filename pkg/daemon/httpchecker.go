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
	"net/http"
	"time"

	"github.com/AthenZ/k8s-athenz-sia/v3/pkg/config"
	"github.com/AthenZ/k8s-athenz-sia/v3/third_party/log"
	"github.com/cenkalti/backoff"
)

// WaitForServerReady waits until the HTTP(S) server can respond to a GET request. Should NOT allow cancelling the retry as shuting down non-ready server may cause deadlock.
func WaitForServerReady(serverAddr string, insecureSkipVerify bool) error {

	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig = &tls.Config{}
	client := &http.Client{Transport: t}

	var url string
	if insecureSkipVerify {
		t.TLSClientConfig.InsecureSkipVerify = true
		url = "https://" + serverAddr
	} else {
		url = "http://" + serverAddr
	}

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

	return backoff.RetryNotify(get, getExponentialBackoff(), func(err error, backoffDelay time.Duration) {
		log.Warnf("Unable to confirm the server ready: %s. Retrying in %s", err.Error(), backoffDelay)
	})
}
