package identity

import (
	"fmt"
	"strings"
	"time"

	"github.com/yahoo/k8s-athenz-identity/pkg/log"

	// using git submodule to import internal package (special package in golang)
	// https://github.com/golang/go/wiki/Modules#can-a-module-depend-on-an-internal-in-another
	athenz "github.com/AthenZ/athenz/libs/go/sia/util"
	internal "github.com/AthenZ/k8s-athenz-sia/pkg/metrics"
)

func Metricsd(idConfig *IdentityConfig, stopChan <-chan struct{}) (error, <-chan struct{}) {
	if stopChan == nil {
		panic(fmt.Errorf("Metricsd: stopChan cannot be empty"))
	}

	if idConfig.Init {
		log.Infof("Metrics exporter is disabled for init mode: address[%s]", idConfig.MetricsServerAddr)
		return nil, nil
	}

	if idConfig.MetricsServerAddr == "" {
		log.Infof("Metrics exporter is disabled with empty options: address[%s]", idConfig.MetricsServerAddr)
		return nil, nil
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
			targetDomain, targetRole, err := athenz.SplitRoleName(domainrole)
			if err != nil {
				log.Warnf("Failed to read element '%s' of given TARGET_DOMAIN_ROLES: %s, err: %s", domainrole, idConfig.TargetDomainRoles, err.Error())
				continue
			}

			fileName := targetDomain + idConfig.RoleCertFilenameDelimiter + targetRole + ".cert.pem"
			exporter.Files = append(exporter.Files, strings.TrimSuffix(idConfig.RoleCertDir, "/")+"/"+fileName)
		}
	}

	go func() {
		err := exporter.ListenAndServe()
		if err != nil {
			log.Errorf("Failed to start metrics exporter: %s", err.Error())
		}
	}()

	shutdownChan := make(chan struct{}, 1)
	go func() {
		defer close(shutdownChan)

		<-stopChan
		err := exporter.Shutdown()
		if err != nil {
			log.Errorf("Failed to shutdown metrics exporter: %s", err.Error())
		}
	}()

	return nil, shutdownChan
}
