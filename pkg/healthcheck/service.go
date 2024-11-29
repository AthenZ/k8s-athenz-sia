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

package healthcheck

import (
	"context"
	"fmt"
	"net/http"
	"runtime"
	"sync"

	"github.com/AthenZ/k8s-athenz-sia/v3/pkg/config"
	"github.com/AthenZ/k8s-athenz-sia/v3/pkg/daemon"
	"github.com/AthenZ/k8s-athenz-sia/v3/third_party/log"
)

type hcService struct {
	shutdownChan chan struct{}
	shutdownWg   sync.WaitGroup

	idCfg           *config.IdentityConfig
	hcServer        *http.Server
	hcServerRunning bool
}

func New(ctx context.Context, idCfg *config.IdentityConfig) (daemon.Daemon, error) {
	if ctx.Err() != nil {
		log.Info("Skipped health check initiation")
		return nil, nil
	}

	hs := &hcService{
		shutdownChan: make(chan struct{}, 1),
		idCfg:        idCfg,
	}

	// check initialization skip
	if idCfg.Init {
		log.Infof("Health check server is disabled for init mode: address[%s]", idCfg.HealthCheckAddr)
		return hs, nil
	}
	if idCfg.HealthCheckAddr == "" {
		log.Infof("Health check server is disabled with empty options: address[%s]", idCfg.HealthCheckAddr)
		return hs, nil
	}

	mux := http.NewServeMux()
	mux.HandleFunc(idCfg.HealthCheckEndpoint, handleHealthCheckRequest)
	hs.hcServer = &http.Server{
		Addr:    idCfg.HealthCheckAddr,
		Handler: mux,
	}

	return hs, nil
}

// Start starts the health check server
func (hs *hcService) Start(ctx context.Context) error {
	if ctx.Err() != nil {
		log.Info("Skipped health check start")
		return nil
	}

	if hs.hcServer != nil {
		log.Infof("Starting health check server[%s]", hs.idCfg.HealthCheckAddr)
		hs.shutdownWg.Add(1)
		go func() {
			defer hs.shutdownWg.Done()
			if err := hs.hcServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Failed to start health check server: %s", err.Error())
			}
			log.Info("Stopped health check server")
		}()

		if err := daemon.WaitForServerReady(hs.hcServer.Addr, false, false); err != nil {
			log.Errorf("Failed to confirm health check server ready: %s", err.Error())
			return err
		}
		hs.hcServerRunning = true
	}

	return nil
}

func (hs *hcService) Shutdown() {
	log.Info("Initiating shutdown of health check daemon ...")
	close(hs.shutdownChan)

	if hs.hcServer != nil {
		// As hs.hcServer should always shutdown forcefully, NO need to check hs.hcServerRunning == true

		forcedCtx, cancel := context.WithCancel(context.Background())
		cancel() // force shutdown health check server without delay
		hs.hcServer.SetKeepAlivesEnabled(false)
		if err := hs.hcServer.Shutdown(forcedCtx); err != nil && err != context.Canceled {
			log.Errorf("Failed to shutdown health check server: %s", err.Error())
		}
	}

	// wait for forceful shutdown
	hs.shutdownWg.Wait()
}

// handleHealthCheckRequest is a handler function for and health check request, which always a HTTP Status OK (200) result
func handleHealthCheckRequest(w http.ResponseWriter, r *http.Request) {
	defer func() {
		// handle panic, reference: https://github.com/golang/go/blob/go1.20.7/src/net/http/server.go#L1851-L1856
		if err := recover(); err != nil && err != http.ErrAbortHandler {
			const size = 64 << 10
			buf := make([]byte, size)
			buf = buf[:runtime.Stack(buf, false)]
			log.Errorf("http: panic serving %v: %v\n%s", r.RemoteAddr, err, buf)

			w.WriteHeader(http.StatusInternalServerError)
		}
	}()

	if r.Method == http.MethodGet {
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-type", "text/plain; charset=utf-8")
		_, err := fmt.Fprint(w, http.StatusText(http.StatusOK))
		if err != nil {
			log.Errorf("Failed to write health check server response: %v", err)
		}
	}
}
