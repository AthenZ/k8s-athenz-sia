package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/pkg/errors"
	"github.com/yahoo/k8s-athenz-identity/pkg/log"
	"github.com/yahoo/k8s-athenz-identity/pkg/util"

	"github.com/AthenZ/k8s-athenz-sia/pkg/identity"
)

const serviceName = "athenz-sia"

var errEarlyExit = fmt.Errorf("early exit")

var (
	VERSION    string
	BUILD_DATE string
)

// printVersion returns the version and the built date of the executable itself
func printVersion() {
	if VERSION == "" || BUILD_DATE == "" {
		fmt.Printf("(development version)\n")
	} else {
		fmt.Printf("Version: %s\n", VERSION)
		fmt.Printf("Build Date: %s\n", BUILD_DATE)
		fmt.Println("===== Default Values =====")
		fmt.Printf("Athenz Endpoint: %s\n", identity.DEFAULT_ENDPOINT)
		fmt.Printf("Certificate SANs DNS Suffix: %s\n", identity.DEFAULT_DNS_SUFFIX)
		fmt.Printf("Country: %s\n", identity.DEFAULT_COUNTRY)
		fmt.Printf("Province: %s\n", identity.DEFAULT_PROVINCE)
		fmt.Printf("Organization: %s\n", identity.DEFAULT_ORGANIZATION)
		fmt.Printf("OrganizationalUnit: %s\n", identity.DEFAULT_ORGANIZATIONAL_UNIT)
		fmt.Printf("Role Cert Expiry Time Buffer Minutes: %d\n", identity.DEFAULT_ROLE_CERT_EXPIRY_TIME_BUFFER_MINUTES_INT)
		fmt.Printf("Role Cert Filename Delimiter: %s\n", identity.DEFAULT_ROLE_CERT_FILENAME_DELIMITER)
		fmt.Printf("Role Token Header: %s\n", identity.DEFAULT_ROLE_AUTH_HEADER)
	}
}

// envOrDefault returns the value of the supplied variable or a default string.
func envOrDefault(name string, defaultValue string) string {
	v := os.Getenv(name)
	if v == "" {
		return defaultValue
	}
	return v
}

// parseFlags parses ENV and cmd line args and returns an IdentityConfig object
func parseFlags(program string, args []string) (*identity.IdentityConfig, error) {
	var (
		mode                      = envOrDefault("MODE", "init")
		endpoint                  = envOrDefault("ENDPOINT", identity.DEFAULT_ENDPOINT)
		providerService           = envOrDefault("PROVIDER_SERVICE", "")
		dnsSuffix                 = envOrDefault("DNS_SUFFIX", identity.DEFAULT_DNS_SUFFIX)
		refreshInterval           = envOrDefault("REFRESH_INTERVAL", "24h")
		delayJitterSeconds, _     = strconv.ParseInt(envOrDefault("DELAY_JITTER_SECONDS", "0"), 10, 64)
		keyFile                   = envOrDefault("KEY_FILE", "")
		certFile                  = envOrDefault("CERT_FILE", "")
		caCertFile                = envOrDefault("CA_CERT_FILE", "")
		intermediateCertBundle    = envOrDefault("INTERMEDIATE_CERT_BUNDLE", identity.DEFAULT_INTERMEDIATE_CERT_BUNDLE)
		logDir                    = envOrDefault("LOG_DIR", "")
		logLevel                  = envOrDefault("LOG_LEVEL", "INFO")
		backup                    = envOrDefault("BACKUP", "read+write")
		certSecret                = envOrDefault("CERT_SECRET", "")
		namespace                 = envOrDefault("NAMESPACE", "")
		athenzDomain              = envOrDefault("ATHENZ_DOMAIN", "")
		athenzPrefix              = envOrDefault("ATHENZ_PREFIX", "")
		athenzSuffix              = envOrDefault("ATHENZ_SUFFIX", "")
		serviceAccount            = envOrDefault("SERVICEACCOUNT", "")
		saTokenFile               = envOrDefault("SA_TOKEN_FILE", "")
		podIP                     = envOrDefault("POD_IP", "127.0.0.1")
		podUID                    = envOrDefault("POD_UID", "")
		serverCACert              = envOrDefault("SERVER_CA_CERT", "")
		targetDomainRoles         = envOrDefault("TARGET_DOMAIN_ROLES", "")
		roleCertDir               = envOrDefault("ROLECERT_DIR", "")
		roleCertFilenameDelimiter = envOrDefault("ROLE_CERT_FILENAME_DELIMITER", identity.DEFAULT_ROLE_CERT_FILENAME_DELIMITER)
		tokenDir                  = envOrDefault("TOKEN_DIR", "")
		roleAuthHeader            = envOrDefault("ROLE_AUTH_HEADER", identity.DEFAULT_ROLE_AUTH_HEADER)
		tokenType                 = envOrDefault("TOKEN_TYPE", "accesstoken")
		tokenRefreshInterval      = envOrDefault("TOKEN_REFRESH_INTERVAL", "30m")
		tokenServerAddr           = envOrDefault("TOKEN_SERVER_ADDR", "")
		metricsServerAddr         = envOrDefault("METRICS_SERVER_ADDR", "")
		deleteInstanceID, _       = strconv.ParseBool(envOrDefault("DELETE_INSTANCE_ID", "true"))
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
			err = errEarlyExit
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
	if pollTokenInterval > 4*time.Hour {
		pollTokenInterval = 4 * time.Hour
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

	return &identity.IdentityConfig{
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
		TokenRefresh:              tri,
		TokenServerAddr:           tokenServerAddr,
		TokenDir:                  tokenDir,
		MetricsServerAddr:         metricsServerAddr,
		DeleteInstanceID:          deleteInstanceID,
	}, nil
}

func main() {
	identity.InitDefaultValues()       // initialize default values
	flag.CommandLine.Parse([]string{}) // initialize glog with defaults
	if len(os.Args) == 2 && os.Args[1] == "version" {
		printVersion()
		return
	}

	certificateChan := make(chan struct{})
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTERM, os.Interrupt)

	idConfig, err := parseFlags(filepath.Base(os.Args[0]), os.Args[1:])
	if err != nil {
		if err == errEarlyExit {
			return
		}
		log.Fatalln(err)
	}
	log.Infoln("Booting up with args", os.Args)

	err = identity.Certificated(idConfig, certificateChan)
	if err != nil && err != errEarlyExit {
		log.Fatalln(err)
	}

	if !idConfig.Init {
		<-ch // wait until receiving os.Signal from channel ch
		log.Println("Shutting down...")
	}

	close(certificateChan)
}
