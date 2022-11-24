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

var VERSION string

var BUILD_DATE string

// printVersion returns the version and the built date of the executable itself
func printVersion() {
	if VERSION == "" || BUILD_DATE == "" {
		fmt.Printf("(development version)\n")
	} else {
		fmt.Printf("Version: %s\n", VERSION)
		fmt.Printf("Build Date: %s\n", BUILD_DATE)
		fmt.Printf("Country: %s\n", identity.DEFAULT_COUNTRY)
		fmt.Printf("Province: %s\n", identity.DEFAULT_PROVINCE)
		fmt.Printf("Organization: %s\n", identity.DEFAULT_ORGANIZATION)
		fmt.Printf("OrganizationalUnit: %s\n", identity.DEFAULT_ORGANIZATIONAL_UNIT)
		fmt.Printf("Role Cert Expiry Time Buffer Minutes: %d\n", identity.DEFAULT_ROLE_CERT_EXPIRY_TIME_BUFFER_MINUTES_INT)
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
		mode                        = envOrDefault("MODE", "init")
		backupMode                  = envOrDefault("BACKUP_MODE", "read")
		endpoint                    = envOrDefault("ENDPOINT", "")
		providerService             = envOrDefault("PROVIDER_SERVICE", "")
		dnsSuffix                   = envOrDefault("DNS_SUFFIX", "")
		refreshInterval             = envOrDefault("REFRESH_INTERVAL", "3s")
		tokenRefreshInterval        = envOrDefault("TOKEN_REFRESH_INTERVAL", "4s")
		delayJitterSeconds, _       = strconv.ParseInt(envOrDefault("DELAY_JITTER_SECONDS", "0"), 10, 64)
		keyFile                     = envOrDefault("KEY_FILE", "/var/run/athenz/service.key.pem")
		certFile                    = envOrDefault("CERT_FILE", "/var/run/athenz/service.cert.pem")
		certSecret                  = envOrDefault("CERT_SECRET", "")
		caCertFile                  = envOrDefault("CA_CERT_FILE", "/var/run/athenz/ca.cert.pem")
		logDir                      = envOrDefault("LOG_DIR", "/var/log/athenz-sia")
		logLevel                    = envOrDefault("LOG_LEVEL", "INFO")
		namespace                   = envOrDefault("NAMESPACE", "")
		serviceAccount              = envOrDefault("SERVICEACCOUNT", "")
		podIP                       = envOrDefault("POD_IP", "")
		podUID                      = envOrDefault("POD_UID", "")
		saTokenFile                 = envOrDefault("SA_TOKEN_FILE", "/var/run/secrets/kubernetes.io/bound-serviceaccount/token")
		serverCACert                = envOrDefault("SERVER_CA_CERT", "")
		roleCertDir                 = envOrDefault("ROLECERT_DIR", "/var/run/athenz/")
		targetDomainRoles           = envOrDefault("TARGET_DOMAIN_ROLES", "")
		tokenServerAddr             = envOrDefault("TOKEN_SERVER_ADDR", ":8880")
		deleteInstanceID, _         = strconv.ParseBool(envOrDefault("DELETE_INSTANCE_ID", "true"))
		skipIdentityProvisioning, _ = strconv.ParseBool(envOrDefault("SKIP_IDENTITY_PROVISIONING", "false"))
	)
	f := flag.NewFlagSet(program, flag.ContinueOnError)
	f.StringVar(&mode, "mode", mode, "mode, must be one of init or refresh")
	f.StringVar(&endpoint, "endpoint", endpoint, "Athenz ZTS endpoint (required)")
	f.StringVar(&providerService, "provider-service", providerService, "Identity Provider service (required)")
	f.StringVar(&dnsSuffix, "dns-suffix", dnsSuffix, "DNS Suffix for certs (required)")
	f.StringVar(&refreshInterval, "refresh-interval", refreshInterval, "cert refresh interval")
	f.StringVar(&tokenRefreshInterval, "token-refresh-interval", tokenRefreshInterval, "token refresh interval")
	f.Int64Var(&delayJitterSeconds, "delay-jitter-seconds", delayJitterSeconds, "delay boot with random jitter within the specified seconds (0 to disable)")
	f.StringVar(&keyFile, "key", keyFile, "key file for the certificate")
	f.StringVar(&certFile, "cert", certFile, "cert file to identity a service")
	f.StringVar(&certSecret, "cert-secret", certSecret, "Kubernetes secret name to backup cert (Backup will be disabled if empty)")
	f.StringVar(&backupMode, "backup-mode", backupMode, "Kubernetes secret backup mode, must be one of read or write (Note: Performing writes with a large number of concurrency may cause unexpected loads on k8s api)")
	f.StringVar(&caCertFile, "out-ca-cert", caCertFile, "CA cert file to write")
	f.StringVar(&logDir, "log-dir", logDir, "directory to store the server log files")
	f.StringVar(&logLevel, "log-level", logLevel, "logging level")
	f.StringVar(&saTokenFile, "sa-token-file", saTokenFile, "bound sa jwt token file location")
	f.StringVar(&serverCACert, "server-ca-cert", serverCACert, "path to CA cert file to verify ZTS server certs")
	f.StringVar(&roleCertDir, "out-rolecert-dir", roleCertDir, "directory to write cert file for role certificates")
	f.StringVar(&targetDomainRoles, "target-domain-roles", targetDomainRoles, "target Athenz roles with domain (e.g. athenz.subdomain:role.admin,sys.auth:role.providers)")
	f.StringVar(&tokenServerAddr, "token-server-addr", tokenServerAddr, "HTTP server address to provide tokens (default :8080)")
	f.BoolVar(&deleteInstanceID, "delete-instance-id", deleteInstanceID, "delete x509 cert record from identity provider when stop signal is sent")
	f.BoolVar(&skipIdentityProvisioning, "skip-identity-provisioning", skipIdentityProvisioning, "skip identity provisioning and use (cert)")

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
		return nil, fmt.Errorf("Invalid mode %q must be one of init or refresh", mode)
	}
	init := mode == "init"
	backup := backupMode == "write"
	if !backup && certSecret == "" {
		log.Infof("Skipping to load/save x509 cert temporary backup from/to kubernetes secret...")
	}

	ri, err := time.ParseDuration(refreshInterval)
	if err != nil {
		return nil, fmt.Errorf("Invalid refresh interval %q, %v", refreshInterval, err)
	}
	tri, err := time.ParseDuration(tokenRefreshInterval)
	if err != nil {
		return nil, fmt.Errorf("Invalid token refresh interval %q, %v", tokenRefreshInterval, err)
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
	if init && err == nil {
		log.Errorf("SIA(init) detected the existence of X.509 cert at %s", certFile)
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
		return nil, errors.New("X.509 certificate already exists.")
	}
	if !init && err != nil {
		return nil, errors.Wrap(err, "unable to read key and cert")
	}

	return &identity.IdentityConfig{
		Init:                     init,
		Backup:                   backup,
		KeyFile:                  keyFile,
		CertFile:                 certFile,
		CertSecret:               certSecret,
		CaCertFile:               caCertFile,
		Refresh:                  ri,
		TokenRefresh:             tri,
		DelayJitterSeconds:       delayJitterSeconds,
		Reloader:                 reloader,
		ServerCACert:             serverCACert,
		SaTokenFile:              saTokenFile,
		Endpoint:                 endpoint,
		ProviderService:          providerService,
		DNSSuffix:                dnsSuffix,
		Namespace:                namespace,
		ServiceAccount:           serviceAccount,
		PodIP:                    podIP,
		PodUID:                   podUID,
		RoleCertDir:              roleCertDir,
		TargetDomainRoles:        targetDomainRoles,
		TokenServerAddr:          tokenServerAddr,
		DeleteInstanceID:         deleteInstanceID,
		SkipIdentityProvisioning: skipIdentityProvisioning,
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
	tokenChan := make(chan struct{})
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
	err = identity.Tokend(idConfig, tokenChan)
	if err != nil && err != errEarlyExit {
		log.Fatalln(err)
	}

	<-ch // wait until receiving os.Signal from channel ch
	log.Println("Shutting down...")
	close(certificateChan)
	close(tokenChan)
}
