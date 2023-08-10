// Copyright 2023 Yahoo Japan Corporation
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

	log.Infof("Starting health check server[%s]", idConfig.HealthCheckAddr)

	healthCheckServer := &http.Server{
		Addr:    idConfig.HealthCheckAddr,
		Handler: createHealthCheckServiceMux(idConfig.HealthCheckEndpoint),
	}

	serverDone := make(chan struct{}, 1)
	go func() {
		log.Infof("Starting health check server[%s]", idConfig.HealthCheckAddr)
		if err := healthCheckServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Errorf("Failed to start health check server: %s", err.Error())
		}
		close(serverDone)
	}()

	shutdownChan := make(chan struct{}, 1)
	go func() {
		defer close(shutdownChan)

		<-stopChan
		log.Info("Health check server will shutdown")
		ctx, cancel := context.WithTimeout(context.Background(), idConfig.ShutdownTimeout)
		defer cancel()
		healthCheckServer.SetKeepAlivesEnabled(false)
		if err := healthCheckServer.Shutdown(ctx); err != nil {
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
	if r.Method == http.MethodGet {
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-type", "text/plain; charset=utf-8")
		_, err := fmt.Fprint(w, http.StatusText(http.StatusOK))
		if err != nil {
			log.Fatal(err)
		}
	}
}
