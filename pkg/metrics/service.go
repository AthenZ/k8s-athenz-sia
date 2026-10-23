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

	"github.com/AthenZ/k8s-athenz-sia/v3/pkg/config"
	"github.com/AthenZ/k8s-athenz-sia/v3/pkg/daemon"
	"github.com/AthenZ/k8s-athenz-sia/v3/third_party/log"

	extutil "github.com/AthenZ/k8s-athenz-sia/v3/pkg/util"
	"github.com/enix/x509-certificate-exporter/v4/pkg/cert"
	"github.com/enix/x509-certificate-exporter/v4/pkg/cert/pem"
	"github.com/enix/x509-certificate-exporter/v4/pkg/fileglob"
	"github.com/enix/x509-certificate-exporter/v4/pkg/registry"
	"github.com/enix/x509-certificate-exporter/v4/pkg/source/file"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type metricsService struct {
	shutdownChan chan struct{}
	shutdownWg   sync.WaitGroup

	idCfg           *config.IdentityConfig
	exporter        *registry.Registry
	source          *file.Source
	firstSyncDone   chan struct{}
	server          *http.Server
	cancel          context.CancelFunc
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

	files := []string{}
	if idCfg.ServiceCert.CopperArgos.Use {
		files = append(files, idCfg.ServiceCert.CopperArgos.Cert.Paths...)
	}
	if idCfg.ServiceCert.LocalCert.Use {
		files = append(files, idCfg.ServiceCert.LocalCert.CertPath)
	}
	if idCfg.CaCertFile != "" {
		files = append(files, idCfg.CaCertFile)
	}

	if idCfg.RoleCert.Use {
		for _, dr := range idCfg.RoleCert.TargetDomainRoles {
			fileName, err := extutil.GeneratePath(idCfg.RoleCert.Format, dr.Domain, dr.Role, idCfg.RoleCert.Delimiter)
			if err != nil {
				return nil, fmt.Errorf("failed to generate path for role cert with format [%s], domain [%s], role [%s], delimiter [%s]: %w", idCfg.RoleCert.Format, dr.Domain, dr.Role, idCfg.RoleCert.Delimiter, err)
			}
			files = append(files, fileName)
		}
	}

	patterns := make([]fileglob.Pattern, 0, len(files))
	for _, path := range files {
		if path == "" {
			continue
		}
		pattern, err := fileglob.Compile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to compile certificate path [%s]: %w", path, err)
		}
		patterns = append(patterns, pattern)
	}

	ms.exporter = registry.New(registry.Config{
		ExposeRelative:     true,
		ExposePerCertError: true,
		ExposeNotBefore:    true,
		ExposeExpired:      true,
	}, nil)
	ms.exporter.PreInitBundleSource(cert.KindFile, "files")
	ms.firstSyncDone = make(chan struct{})
	ms.source = file.New(file.Options{
		Name:              "files",
		Patterns:          patterns,
		Formats:           []cert.FormatParser{pem.New()},
		FollowSymlinks:    true,
		FollowSymlinkDirs: true,
		FirstSyncDone:     ms.firstSyncDone,
		OnReady: func(up bool) {
			ms.exporter.MarkSourceUp(cert.KindFile, "files", up)
		},
	}, nil)
	exporterRegistry := prometheus.NewRegistry()
	if err := exporterRegistry.Register(ms.exporter); err != nil {
		return nil, fmt.Errorf("failed to register certificate metrics: %w", err)
	}
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.InstrumentMetricHandler(prometheus.DefaultRegisterer, promhttp.HandlerFor(
		prometheus.Gatherers{prometheus.DefaultGatherer, exporterRegistry},
		promhttp.HandlerOpts{},
	)))
	ms.server = &http.Server{Addr: idCfg.MetricsServerAddr, Handler: mux}
	return ms, nil
}

// Start starts the metrics exporter
func (ms *metricsService) Start(ctx context.Context) error {
	if ctx.Err() != nil {
		log.Info("Skipped metrics exporter start")
		return nil
	}

	if ms.exporter != nil {
		sourceCtx, cancel := context.WithCancel(ctx)
		ms.cancel = cancel
		ms.shutdownWg.Add(1)
		go func() {
			defer ms.shutdownWg.Done()
			if err := ms.source.Run(sourceCtx, ms.exporter); err != nil && sourceCtx.Err() == nil {
				log.Errorf("Failed to monitor certificate files: %s", err.Error())
			}
		}()
		select {
		case <-ms.firstSyncDone:
		case <-sourceCtx.Done():
			return sourceCtx.Err()
		}

		log.Infof("Starting metrics exporter server[%s]", ms.idCfg.MetricsServerAddr)
		ms.shutdownWg.Add(1)
		go func() {
			defer ms.shutdownWg.Done()
			if err := ms.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Failed to start metrics exporter server: %s", err.Error())
			}
			log.Info("Stopped metrics exporter server")
		}()

		if err := daemon.WaitForServerReady(ms.server.Addr, false, false); err != nil {
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

	if ms.cancel != nil {
		ms.cancel()
	}
	if ms.server != nil {
		err := ms.server.Shutdown(context.Background())
		if err != nil {
			log.Errorf("Failed to shutdown metrics exporter server: %s", err.Error())
		}
	}

	// wait for graceful shutdown
	ms.shutdownWg.Wait()
}
