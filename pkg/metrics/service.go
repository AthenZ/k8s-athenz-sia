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

package metrics

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/AthenZ/k8s-athenz-sia/v3/pkg/config"
	"github.com/AthenZ/k8s-athenz-sia/v3/pkg/daemon"
	"github.com/AthenZ/k8s-athenz-sia/v3/third_party/log"

	// using git submodule to import internal package (special package in golang)
	// https://github.com/golang/go/wiki/Modules#can-a-module-depend-on-an-internal-in-another
	"github.com/AthenZ/k8s-athenz-sia/v3/pkg/metrics/internal"
	extutil "github.com/AthenZ/k8s-athenz-sia/v3/pkg/util"
)

type metricsService struct {
	shutdownChan chan struct{}
	shutdownWg   sync.WaitGroup

	idCfg           *config.IdentityConfig
	exporter        *internal.Exporter
	exporterRunning bool
}

func New(ctx context.Context, idCfg *config.IdentityConfig) (daemon.Daemon, error) {
	if ctx.Err() != nil {
		log.Info("Skipped metrics exporter initiation")
		return nil, nil
	}

	ms := &metricsService{
		shutdownChan: make(chan struct{}, 1),
		idCfg:        idCfg,
	}

	// check initialization skip
	if idCfg.Init {
		log.Infof("Metrics exporter is disabled for init mode: address[%s]", idCfg.MetricsServerAddr)
		return ms, nil
	}
	if idCfg.MetricsServerAddr == "" {
		log.Infof("Metrics exporter is disabled with empty options: address[%s]", idCfg.MetricsServerAddr)
		return ms, nil
	}

	// https://github.com/enix/x509-certificate-exporter
	// https://github.com/enix/x509-certificate-exporter/blob/main/cmd/x509-certificate-exporter/main.go
	// https://github.com/enix/x509-certificate-exporter/blob/beb88b34b490add4015c8b380d975eb9cb340d44/internal/exporter.go#L26
	exporter := internal.Exporter{
		ListenAddress: idCfg.MetricsServerAddr,
		SystemdSocket: false,
		ConfigFile:    "",
		Files: func() []string {
			files := []string{}
			if idCfg.CertFile != "" {
				files = append(files, idCfg.CertFile)
			}
			if idCfg.CaCertFile != "" {
				files = append(files, idCfg.CaCertFile)
			}
			return files
		}(),
		Directories:           []string{},
		YAMLs:                 []string{},
		TrimPathComponents:    0,
		MaxCacheDuration:      time.Duration(0),
		ExposeRelativeMetrics: true,
		ExposeErrorMetrics:    true,
		KubeSecretTypes: []string{
			"kubernetes.io/tls:tls.crt",
		},
		KubeIncludeNamespaces: []string{},
		KubeExcludeNamespaces: []string{},
		KubeIncludeLabels:     []string{},
		KubeExcludeLabels:     []string{},
	}

	if idCfg.RoleCert.Use {
		for _, dr := range idCfg.RoleCert.TargetDomainRoles {
			fileName, err := extutil.GeneratePath(idCfg.RoleCert.Format, dr.Domain, dr.Role, idCfg.RoleCert.Delimiter)
			if err != nil {
				return nil, fmt.Errorf("failed to generate path for role cert with format [%s], domain [%s], role [%s], delimiter [%s]: %w", idCfg.RoleCert.Format, dr.Domain, dr.Role, idCfg.RoleCert.Delimiter, err)
			}
			exporter.Files = append(exporter.Files, fileName)
		}
	}

	ms.exporter = &exporter
	return ms, nil
}

// Start starts the metrics exporter
func (ms *metricsService) Start(ctx context.Context) error {
	if ctx.Err() != nil {
		log.Info("Skipped metrics exporter start")
		return nil
	}

	if ms.exporter != nil {
		log.Infof("Starting metrics exporter server[%s]", ms.idCfg.MetricsServerAddr)
		ms.shutdownWg.Add(1)
		go func() {
			defer ms.shutdownWg.Done()
			if err := ms.exporter.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Failed to start metrics exporter server: %s", err.Error())
			}
			log.Info("Stopped metrics exporter server")
		}()

		if err := daemon.WaitForServerReady(ms.exporter.ListenAddress, false, false); err != nil {
			log.Errorf("Failed to confirm metrics exporter server ready: %s", err.Error())
			return err
		}
		ms.exporterRunning = true
	}

	return nil
}

func (ms *metricsService) Shutdown() {
	log.Info("Initiating shutdown of metrics exporter daemon ...")
	close(ms.shutdownChan)

	if ms.exporter != nil {
		// As ms.exporter.Shutdown() can ONLY shutdown gracefully, NO need to check ms.exporterRunning == true

		err := ms.exporter.Shutdown()
		// context.Background() is used, no timeout. refer to https://github.com/enix/x509-certificate-exporter/blob/33dd533/internal/exporter.go#L111
		// P.S. Make sure to use the httpChecker to ensure ListenAndServe() is finished before Shutdown() is called. If ListenAndServe() does not finish creating the server object before Shutdown() is called, the internal server field will be nil and Shutdown() be a no-op. ListenAndServe() will block and cause deadlock.
		if err != nil {
			log.Errorf("Failed to shutdown metrics exporter server: %s", err.Error())
		}
	}

	// wait for graceful shutdown
	ms.shutdownWg.Wait()
}
