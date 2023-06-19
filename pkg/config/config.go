package config

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/pkg/errors"

	athenz "github.com/AthenZ/athenz/libs/go/sia/util"

	"github.com/AthenZ/k8s-athenz-sia/third_party/log"
	"github.com/AthenZ/k8s-athenz-sia/third_party/util"
)

// ReadConfig reads YAML, ENV and args, and then returns an IdentityConfig object (precedence: args > ENV > YAML).
func ReadConfig(program string, args []string) (*IdentityConfig, error) {
	return parseFlags(program, args)
}

// (copy from main)
func parseFlags(program string, args []string) (*IdentityConfig, error) {
	var (
		mode                      = athenz.EnvOrDefault("MODE", "init")
		endpoint                  = athenz.EnvOrDefault("ENDPOINT", DEFAULT_ENDPOINT)
		providerService           = athenz.EnvOrDefault("PROVIDER_SERVICE", "")
		dnsSuffix                 = athenz.EnvOrDefault("DNS_SUFFIX", DEFAULT_DNS_SUFFIX)
		refreshInterval           = athenz.EnvOrDefault("REFRESH_INTERVAL", "24h")
		delayJitterSeconds, _     = strconv.ParseInt(athenz.EnvOrDefault("DELAY_JITTER_SECONDS", "0"), 10, 64)
		keyFile                   = athenz.EnvOrDefault("KEY_FILE", "")
		certFile                  = athenz.EnvOrDefault("CERT_FILE", "")
		caCertFile                = athenz.EnvOrDefault("CA_CERT_FILE", "")
		intermediateCertBundle    = athenz.EnvOrDefault("INTERMEDIATE_CERT_BUNDLE", DEFAULT_INTERMEDIATE_CERT_BUNDLE)
		logDir                    = athenz.EnvOrDefault("LOG_DIR", "")
		logLevel                  = athenz.EnvOrDefault("LOG_LEVEL", "INFO")
		backup                    = athenz.EnvOrDefault("BACKUP", "read+write")
		certSecret                = athenz.EnvOrDefault("CERT_SECRET", "")
		namespace                 = athenz.EnvOrDefault("NAMESPACE", "")
		athenzDomain              = athenz.EnvOrDefault("ATHENZ_DOMAIN", "")
		athenzPrefix              = athenz.EnvOrDefault("ATHENZ_PREFIX", "")
		athenzSuffix              = athenz.EnvOrDefault("ATHENZ_SUFFIX", "")
		serviceAccount            = athenz.EnvOrDefault("SERVICEACCOUNT", "")
		saTokenFile               = athenz.EnvOrDefault("SA_TOKEN_FILE", "")
		podIP                     = athenz.EnvOrDefault("POD_IP", "127.0.0.1")
		podUID                    = athenz.EnvOrDefault("POD_UID", "")
		serverCACert              = athenz.EnvOrDefault("SERVER_CA_CERT", "")
		targetDomainRoles         = athenz.EnvOrDefault("TARGET_DOMAIN_ROLES", "")
		roleCertDir               = athenz.EnvOrDefault("ROLECERT_DIR", "")
		roleCertFilenameDelimiter = athenz.EnvOrDefault("ROLE_CERT_FILENAME_DELIMITER", DEFAULT_ROLE_CERT_FILENAME_DELIMITER)
		tokenDir                  = athenz.EnvOrDefault("TOKEN_DIR", "")
		roleAuthHeader            = athenz.EnvOrDefault("ROLE_AUTH_HEADER", DEFAULT_ROLE_AUTH_HEADER)
		tokenType                 = athenz.EnvOrDefault("TOKEN_TYPE", "accesstoken")
		tokenRefreshInterval      = athenz.EnvOrDefault("TOKEN_REFRESH_INTERVAL", "30m")
		tokenServerAddr           = athenz.EnvOrDefault("TOKEN_SERVER_ADDR", "")
		metricsServerAddr         = athenz.EnvOrDefault("METRICS_SERVER_ADDR", "")
		deleteInstanceID, _       = strconv.ParseBool(athenz.EnvOrDefault("DELETE_INSTANCE_ID", "true"))
	)
	f := flag.NewFlagSet(program, flag.ContinueOnError)
	f.StringVar(&mode, "mode", mode, "mode, must be one of init or refresh")
	f.StringVar(&endpoint, "endpoint", endpoint, "Athenz ZTS endpoint (required for identity/role certificate and token provisioning)")
	f.StringVar(&providerService, "provider-service", providerService, "Identity Provider service (required for identity certificate provisioning)")
	f.StringVar(&dnsSuffix, "dns-suffix", dnsSuffix, "DNS Suffix for x509 identity/role certificates (required for identity/role certificate provisioning)")
	f.StringVar(&refreshInterval, "refresh-interval", refreshInterval, "certificate refresh interval")
	f.Int64Var(&delayJitterSeconds, "delay-jitter-seconds", delayJitterSeconds, "delay boot with random jitter within the specified seconds (0 to disable)")
	f.StringVar(&keyFile, "key", keyFile, "key file for the certificate (required)")
	f.StringVar(&certFile, "cert", certFile, "certificate file to identity a service (required)")
	f.StringVar(&caCertFile, "out-ca-cert", caCertFile, "CA certificate file to write")
	f.StringVar(&logDir, "log-dir", logDir, "directory to store the log files")
	f.StringVar(&logLevel, "log-level", logLevel, "logging level")
	f.StringVar(&backup, "backup", backup, "backup certificate to Kubernetes secret (\"read\", \"write\" or \"read+write\", must be run uniquely for each secret to prevent conflict)")
	f.StringVar(&certSecret, "cert-secret", certSecret, "Kubernetes secret name to backup certificate (backup will be disabled with empty)")
	f.StringVar(&saTokenFile, "sa-token-file", saTokenFile, "bound sa jwt token file location (required for identity certificate provisioning)")
	f.StringVar(&serverCACert, "server-ca-cert", serverCACert, "path to CA certificate file to verify ZTS server certs")
	f.StringVar(&targetDomainRoles, "target-domain-roles", targetDomainRoles, "target Athenz roles with domain (e.g. athenz.subdomain"+roleCertFilenameDelimiter+"admin,sys.auth"+roleCertFilenameDelimiter+"providers) (required for role certificate and token provisioning)")
	f.StringVar(&roleCertDir, "rolecert-dir", roleCertDir, "directory to write role certificate files (required for role certificate provisioning)")
	f.StringVar(&tokenDir, "token-dir", tokenDir, "directory to write token files")
	f.StringVar(&tokenType, "token-type", tokenType, "type of the role token to request (\"roletoken\", \"accesstoken\" or \"roletoken+accesstoken\")")
	f.StringVar(&tokenRefreshInterval, "token-refresh-interval", tokenRefreshInterval, "token refresh interval")
	f.StringVar(&tokenServerAddr, "token-server-addr", tokenServerAddr, "HTTP server address to provide tokens (required for token provisioning)")
	f.StringVar(&metricsServerAddr, "metrics-server-addr", metricsServerAddr, "HTTP server address to provide metrics")
	f.BoolVar(&deleteInstanceID, "delete-instance-id", deleteInstanceID, "delete x509 certificate record from identity provider when stop signal is sent")

	err := f.Parse(args)
	if err != nil {
		if err == flag.ErrHelp {
			return nil, err
		}
		log.InitLogger(filepath.Join(logDir, fmt.Sprintf("%s.%s.log", serviceName, logLevel)), logLevel, true)
		return nil, err
	}
	log.InitLogger(filepath.Join(logDir, fmt.Sprintf("%s.%s.log", serviceName, logLevel)), logLevel, true)

	if !(mode == "init" || mode == "refresh") {
		return nil, fmt.Errorf("Invalid mode [%q] must be one of \"init\" or \"refresh\"", mode)
	}
	init := mode == "init"

	ri, err := time.ParseDuration(refreshInterval)
	if err != nil {
		return nil, fmt.Errorf("Invalid refresh interval [%q], %v", refreshInterval, err)
	}
	tri, err := time.ParseDuration(tokenRefreshInterval)
	if err != nil {
		return nil, fmt.Errorf("Invalid token refresh interval [%q], %v", tokenRefreshInterval, err)
	}

	pollInterval := ri
	if pollInterval > util.DefaultPollInterval {
		pollInterval = util.DefaultPollInterval
	}
	pollTokenInterval := tri
	if pollTokenInterval > DEFAULT_POLL_TOKEN_INTERVAL {
		pollTokenInterval = DEFAULT_POLL_TOKEN_INTERVAL
	}
	reloader, err := util.NewCertReloader(util.ReloadConfig{
		KeyFile:      keyFile,
		CertFile:     certFile,
		Logger:       log.Infof,
		PollInterval: pollInterval,
	})

	// During the init flow if X.509 cert(and key) already exists,
	//   - someone is attempting to run init after a pod has been started
	//   - pod sandbox crashed and kubelet runs the init container
	// SIA does not have enough information to differentiate between the two situations.
	// The idea is to delegate the decision to re-issue the X.509 certificate to the identity provider
	// In the case when the podIP changes after a pod sandbox crash, the new pod IP might not have propagated yet
	// to the kube and kubelet APIs. So, we might end up getting an X.509 certificate with the old pod IP.
	// To avoid this, we fail the current run with an error to force SYNC the status on the pod resource and let
	// the subsequent retry for the init container to attempt to get a new certificate from the identity provider.
	if init && err == nil && providerService != "" {
		log.Errorf("SIA(init) detected the existence of X.509 certificate at %s", certFile)
		cert, err := reloader.GetLatestCertificate()
		if err != nil {
			log.Infof("[X.509 Certificate] Subject: %v, DNS SANs: %v, IPs: %v", cert.Leaf.Subject, cert.Leaf.DNSNames, cert.Leaf.IPAddresses)
		}
		log.Infof("Deleting the existing key and cert...")
		if err := os.Remove(certFile); err != nil {
			log.Errorf("Error deleting %s file: %s", certFile, err.Error())
		}
		if err := os.Remove(keyFile); err != nil {
			log.Errorf("Error deleting %s file: %s", keyFile, err.Error())
		}
		return nil, errors.New("Deleted X.509 certificate that already existed.")
	}
	if !init && err != nil {
		return nil, errors.Wrap(err, "unable to read key and cert")
	}

	return &IdentityConfig{
		Init:                      init,
		Endpoint:                  endpoint,
		ProviderService:           providerService,
		DNSSuffix:                 dnsSuffix,
		Refresh:                   ri,
		DelayJitterSeconds:        delayJitterSeconds,
		KeyFile:                   keyFile,
		CertFile:                  certFile,
		CaCertFile:                caCertFile,
		IntermediateCertBundle:    intermediateCertBundle,
		Backup:                    backup,
		CertSecret:                certSecret,
		Namespace:                 namespace,
		AthenzDomain:              athenzDomain,
		AthenzPrefix:              athenzPrefix,
		AthenzSuffix:              athenzSuffix,
		ServiceAccount:            serviceAccount,
		SaTokenFile:               saTokenFile,
		PodIP:                     podIP,
		PodUID:                    podUID,
		Reloader:                  reloader,
		ServerCACert:              serverCACert,
		TargetDomainRoles:         targetDomainRoles,
		RoleCertDir:               roleCertDir,
		RoleCertFilenameDelimiter: roleCertFilenameDelimiter,
		RoleAuthHeader:            roleAuthHeader,
		TokenType:                 tokenType,
		TokenRefresh:              pollTokenInterval,
		TokenServerAddr:           tokenServerAddr,
		TokenDir:                  tokenDir,
		MetricsServerAddr:         metricsServerAddr,
		DeleteInstanceID:          deleteInstanceID,
	}, nil
}