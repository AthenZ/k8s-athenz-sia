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

package identity

import (
	"context"
	"fmt"
	"net/http"
	"runtime"

	"github.com/AthenZ/k8s-athenz-sia/v3/pkg/config"
	"github.com/AthenZ/k8s-athenz-sia/v3/third_party/log"
)

func Healthcheckd(idConfig *config.IdentityConfig, stopChan <-chan struct{}) (error, <-chan struct{}) {
	if stopChan == nil {
		panic(fmt.Errorf("Healthcheckd: stopChan cannot be empty"))
	}

	if idConfig.Init {
		log.Infof("Health check server is disabled for init mode: address[%s]", idConfig.HealthCheckAddr)
		return nil, nil
	}

	if idConfig.HealthCheckAddr == "" {
		log.Infof("Health check server is disabled with empty options: address[%s]", idConfig.HealthCheckAddr)
		return nil, nil
	}

	healthCheckServer := &http.Server{
		Addr:    idConfig.HealthCheckAddr,
		Handler: createHealthCheckServiceMux(idConfig.HealthCheckEndpoint),
	}

	serverDone := make(chan struct{}, 1)
	go func() {
		log.Infof("Starting health check server[%s]", idConfig.HealthCheckAddr)
		if err := healthCheckServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start health check server: %s", err.Error())
		}
		close(serverDone)
	}()

	shutdownChan := make(chan struct{}, 1)
	go func() {
		defer close(shutdownChan)

		<-stopChan
		log.Info("Initiating shutdown of health check daemon ...")
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // force shutdown health check server without delay
		healthCheckServer.SetKeepAlivesEnabled(false)
		if err := healthCheckServer.Shutdown(ctx); err != nil && err != context.Canceled {
			log.Errorf("Failed to shutdown health check server: %s", err.Error())
		}
		<-serverDone
	}()

	return nil, shutdownChan
}

// createHealthCheckServiceMux return a *http.ServeMux object
// The function will register the health check server handler for given pattern, and return
func createHealthCheckServiceMux(pattern string) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc(pattern, handleHealthCheckRequest)
	return mux
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
