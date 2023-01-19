package identity

import (
	"time"

	internal "github.com/AthenZ/k8s-athenz-sia/pkg/metrics"
	"github.com/yahoo/k8s-athenz-identity/pkg/log"
)

func Metricsd(idConfig *IdentityConfig, stopChan <-chan struct{}) error {

	if !idConfig.Init {

		log.Infof("Starting metrics exporter server")

		// enix/x509-certificate-exporter
		// https://github.com/enix/x509-certificate-exporter/blob/main/cmd/x509-certificate-exporter/main.go
		// https://github.com/enix/x509-certificate-exporter/blob/beb88b34b490add4015c8b380d975eb9cb340d44/internal/exporter.go#L26
		exporter := internal.Exporter{
			ListenAddress:         idConfig.MetricsServerAddr,
			SystemdSocket:         false,
			ConfigFile:            "",
			Files:                 []string{},
			Directories:           []string{},
			YAMLs:                 []string{},
			TrimPathComponents:    0,
			MaxCacheDuration:      time.Duration(0),
			ExposeRelativeMetrics: true,
			ExposeErrorMetrics:    true,
			KubeSecretTypes:       []string{},
			KubeIncludeNamespaces: []string{},
			KubeExcludeNamespaces: []string{},
			KubeIncludeLabels:     []string{},
			KubeExcludeLabels:     []string{},
		}

		go func() {
			err := exporter.ListenAndServe()
			if err != nil {
				log.Errorf("Failed to start metrics exporter server: %s", err.Error())
			}
		}()
	}

	return nil
}
