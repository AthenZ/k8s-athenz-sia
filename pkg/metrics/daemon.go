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
	"strings"
	"sync"
	"time"

	"github.com/AthenZ/k8s-athenz-sia/v3/pkg/config"
	"github.com/AthenZ/k8s-athenz-sia/v3/pkg/daemon"
	"github.com/AthenZ/k8s-athenz-sia/v3/third_party/log"

	// using git submodule to import internal package (special package in golang)
	// https://github.com/golang/go/wiki/Modules#can-a-module-depend-on-an-internal-in-another
	"github.com/AthenZ/k8s-athenz-sia/v3/pkg/metrics/internal"
)

type metricsService struct {
	shutdownChan chan struct{}
	shutdownWg   sync.WaitGroup

	idCfg           *config.IdentityConfig
	exporter        *internal.Exporter
	exporterRunning bool
}

func New(ctx context.Context, idCfg *config.IdentityConfig) (error, daemon.Daemon) {
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
		return nil, ms
	}
	if idCfg.MetricsServerAddr == "" {
		log.Infof("Metrics exporter is disabled with empty options: address[%s]", idCfg.MetricsServerAddr)
		return nil, ms
	}

	// https://github.com/enix/x509-certificate-exporter
	// https://github.com/enix/x509-certificate-exporter/blob/main/cmd/x509-certificate-exporter/main.go
	// https://github.com/enix/x509-certificate-exporter/blob/beb88b34b490add4015c8b380d975eb9cb340d44/internal/exporter.go#L26
	exporter := internal.Exporter{
		ListenAddress: idCfg.MetricsServerAddr,
		SystemdSocket: false,
		ConfigFile:    "",
		Files: []string{
			idCfg.CertFile,
			idCfg.CaCertFile,
		},
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

	if len(idCfg.TargetDomainRoles) != 0 && idCfg.RoleCertDir != "" {
		for _, dr := range idCfg.TargetDomainRoles {
			fileName := dr.Domain + idCfg.RoleCertFilenameDelimiter + dr.Role + ".cert.pem"
			exporter.Files = append(exporter.Files, strings.TrimSuffix(idCfg.RoleCertDir, "/")+"/"+fileName)
		}
	}

	ms.exporter = &exporter
	return nil, ms
}

// Start starts the metrics exporter
func (ms *metricsService) Start(ctx context.Context) error {
	if ctx.Err() != nil {
		log.Info("Skipped metrics exporter start")
		return nil
	}

	if ms.exporter != nil {
		log.Infof("Starting metrics exporter[%s]", ms.idCfg.MetricsServerAddr)
		ms.shutdownWg.Add(1)
		go func() {
			defer ms.shutdownWg.Done()
			if err := ms.exporter.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Failed to start metrics exporter: %s", err.Error())
			}
		}()
	}

	// TODO: check server running status
	ms.exporterRunning = true

	return fmt.Errorf("❌❌❌❌❌❌❌❌❌❌❌❌❌❌❌")

	return nil
}

func (ms *metricsService) Shutdown() {
	log.Info("Initiating shutdown of metrics exporter daemon ...")
	close(ms.shutdownChan)

	if ms.exporter != nil && ms.exporterRunning {
		err := ms.exporter.Shutdown() // context.Background() is used, no timeout
		if err != nil {
			log.Errorf("Failed to shutdown metrics exporter: %s", err.Error())
		}
		log.Info("Stopped metrics exporter server")
	}

	// wait for graceful shutdown
	ms.shutdownWg.Wait()
}
