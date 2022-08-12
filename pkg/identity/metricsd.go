package identity

import (
	"strings"
	"time"

	internal "github.com/AthenZ/k8s-athenz-sia/pkg/metrics"
	"github.com/yahoo/k8s-athenz-identity/pkg/log"
)

func Metricsd(idConfig *IdentityConfig, stopChan <-chan struct{}) error {

	if idConfig.Init {
		log.Infof("Metrics exporter is disabled for init mode: address[%s]", idConfig.MetricsServerAddr)
		return nil
	}

	if idConfig.MetricsServerAddr == "" {
		log.Infof("Metrics exporter is disabled with empty options: address[%s]", idConfig.MetricsServerAddr)
		return nil
	}

	log.Infof("Starting metrics exporter[%s]", idConfig.MetricsServerAddr)

	// https://github.com/enix/x509-certificate-exporter
	// https://github.com/enix/x509-certificate-exporter/blob/main/cmd/x509-certificate-exporter/main.go
	// https://github.com/enix/x509-certificate-exporter/blob/beb88b34b490add4015c8b380d975eb9cb340d44/internal/exporter.go#L26
	exporter := internal.Exporter{
		ListenAddress: idConfig.MetricsServerAddr,
		SystemdSocket: false,
		ConfigFile:    "",
		Files: []string{
			idConfig.CertFile,
			idConfig.CaCertFile,
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

	if idConfig.TargetDomainRoles != "" && idConfig.RoleCertDir != "" {
		for _, domainrole := range strings.Split(idConfig.TargetDomainRoles, ",") {
			exporter.Files = append(exporter.Files, strings.TrimSuffix(idConfig.RoleCertDir, "/")+"/"+domainrole+".cert.pem")
		}
	}

	go func() {
		err := exporter.ListenAndServe()
		if err != nil {
			log.Errorf("Failed to start metrics exporter: %s", err.Error())
		}
	}()

	return nil
}
