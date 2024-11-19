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
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/pkg/errors"
)

var DefaultPollInterval = 1 * time.Second // 1s default interval to allow 1m cert refreshes

// LogFn allows customized logging.
type LogFn func(format string, args ...interface{})

// CertReloader reloads the (key, cert) pair from the filesystem when
// the cert file is updated.
type CertReloader struct {
	l            sync.RWMutex
	certFile     string
	keyFile      string
	cert         *tls.Certificate
	certPEM      []byte
	keyPEM       []byte
	mtime        time.Time
	pollInterval time.Duration
	logger       LogFn
	stop         chan struct{}
}

// GetLatestCertificate returns the latest known certificate.
func (w *CertReloader) GetLatestCertificate() (*tls.Certificate, error) {
	w.l.RLock()
	c := w.cert
	w.l.RUnlock()
	return c, nil
}

// GetLatestKeyAndCert returns the latest known key and certificate in raw bytes.
func (w *CertReloader) GetLatestKeyAndCert() ([]byte, []byte, error) {
	w.l.RLock()
	k := w.keyPEM
	c := w.certPEM
	w.l.RUnlock()
	return k, c, nil
}

// Close stops the background refresh.
func (w *CertReloader) Close() error {
	w.stop <- struct{}{}
	return nil
}

func (w *CertReloader) maybeReload() error {
	st, err := os.Stat(w.certFile)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("unable to stat %s", w.certFile))
	}
	if !st.ModTime().After(w.mtime) {
		return nil
	}
	cert, err := tls.LoadX509KeyPair(w.certFile, w.keyFile)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("unable to load cert from %s,%s", w.certFile, w.keyFile))
	}
	certPEM, err := os.ReadFile(w.certFile)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("unable to load cert from %s", w.certFile))
	}
	keyPEM, err := os.ReadFile(w.keyFile)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("unable to load key from %s", w.keyFile))
	}
	w.l.Lock()
	w.cert = &cert
	w.certPEM = certPEM
	w.keyPEM = keyPEM
	w.mtime = st.ModTime()
	w.l.Unlock()
	w.logger("certs reloaded from local file: key[%s], cert[%s] at %v", w.keyFile, w.certFile, time.Now())
	return nil
}

func (w *CertReloader) pollRefresh() error {
	poll := time.NewTicker(w.pollInterval)
	defer poll.Stop()
	for {
		select {
		case <-poll.C:
			if err := w.maybeReload(); err != nil {
				w.logger("cert reload error from local file: key[%s], cert[%s]: %v\n", w.keyFile, w.certFile, err)
			}
		case <-w.stop:
			return nil
		}
	}
}

// UpdateCertificate update certificate and key in cert reloader.
func (w *CertReloader) UpdateCertificate(certPEM []byte, keyPEM []byte) error {
	w.l.Lock()
	defer w.l.Unlock()

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return errors.Wrap(err, "unable to create tls.Certificate from provided PEM data")
	}

	w.cert = &cert
	w.certPEM = certPEM
	w.keyPEM = keyPEM
	w.mtime = time.Now()

	w.logger("certs updated at %v", w.mtime)

	return nil
}

// ReloadConfig contains the config for cert reload.
type ReloadConfig struct {
	Init            bool
	ProviderService string
	CertFile        string // the cert file
	KeyFile         string // the key file
	Logger          LogFn  // custom log function for errors, optional
	PollInterval    time.Duration
}

// NewCertReloader returns a CertReloader that reloads the (key, cert) pair whenever
// the cert file changes on the filesystem.
func NewCertReloader(config ReloadConfig) (*CertReloader, error) {
	if config.Logger == nil {
		config.Logger = log.Printf
	}
	if config.PollInterval == 0 {
		config.PollInterval = time.Duration(DefaultPollInterval)
	}
	r := &CertReloader{
		certFile:     config.CertFile,
		keyFile:      config.KeyFile,
		logger:       config.Logger,
		pollInterval: config.PollInterval,
		stop:         make(chan struct{}, 10),
	}
	// load once to ensure files are good.
	if err := r.maybeReload(); err != nil {
		// In init mode, return initialized CertReloader and error to confirm non-existence of files.
		if config.Init {
			return r, err
		}
		return nil, err
	}

	// If the following condition is met, the cert reloader will not be used to reload certificates:
	//   - SIA does not use identityd to issue certificates (or fig.ProviderService == "")
	//   - File paths for certificates and keys are provided. (or config.CertFile != "" && config.KeyFile != "")
	// TODO: Issue created based on this: https://github.com/AthenZ/k8s-athenz-sia/issues/113
	if config.ProviderService == "" && config.CertFile != "" && config.KeyFile != "" {
		go r.pollRefresh()
	}
	return r, nil
}
