package config

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/pkg/errors"

	athenz "github.com/AthenZ/athenz/libs/go/sia/util"
	"github.com/AthenZ/k8s-athenz-sia/pkg/config/file"
	"github.com/AthenZ/k8s-athenz-sia/third_party/log"
	"github.com/AthenZ/k8s-athenz-sia/third_party/util"
)

var ErrHelp = flag.ErrHelp
var ErrVersion = errors.New("flag: version requested")

// LoadConfig reads YAML, ENV and args, and then returns an IdentityConfig object (precedence: args > ENV > YAML).
func LoadConfig(program string, args []string) (*IdentityConfig, error) {

	// https://github.com/AthenZ/k8s-athenz-sia/blob/c06c60df9e46caf7e0318e7be50257d2527c80e7/cmd/athenz-sia/main.go#LL226C24-L226C24
	flag.CommandLine.Parse([]string{}) // initialize glog with defaults

	// read file path ONLY to alllow reading config file before args
	pathOnlyCfg := DefaultIdentityConfig()
	if err := pathOnlyCfg.loadFromFlag(program, args); err != nil {
		return nil, err
	}

	// load with reverse precedence order
	idConfig := DefaultIdentityConfig()
	if err := idConfig.loadFromYAML(pathOnlyCfg.rawSidecarConfigPath); err != nil {
		return nil, err
	}
	if err := idConfig.loadFromENV(); err != nil {
		return nil, err
	}
	if err := idConfig.loadFromFlag(program, args); err != nil {
		return nil, err
	}

	if err := idConfig.validateAndInit(); err != nil {
		return nil, err
	}
	return idConfig, nil
}

func (idConfig *IdentityConfig) loadFromYAML(configFilePath string) error {

	yamlCfg, err := file.New(configFilePath)
	if err != nil {
		if !os.IsNotExist(err) || configFilePath != DEFAULT_SIDECAR_CONFIG_PATH {
			return err
		}
		// skip if config file IsNotExist AND file path == default
		return nil
	}

	// TODO
	// yamlCfg.RoleToken.Enable
	idConfig.Endpoint = yamlCfg.RoleToken.AthenzURL
	// yamlCfg.RoleToken.AthenzCAPath
	// yamlCfg.RoleToken.CertPath
	// yamlCfg.RoleToken.CertKeyPath
	// yamlCfg.RoleToken.Expiry
	// yamlCfg.RoleToken.RefreshPeriod

	return nil
}

func (idConfig *IdentityConfig) loadFromENV() error {
	loadEnv := func(envName string, valuePtr *string) {
		*valuePtr = athenz.EnvOrDefault(envName, *valuePtr)
	}

	loadEnv("MODE", &idConfig.rawMode)
	loadEnv("ENDPOINT", &idConfig.Endpoint)
	loadEnv("PROVIDER_SERVICE", &idConfig.ProviderService)
	loadEnv("DNS_SUFFIX", &idConfig.DNSSuffix)
	loadEnv("REFRESH_INTERVAL", &idConfig.rawRefresh)
	loadEnv("DELAY_JITTER_SECONDS", &idConfig.rawDelayJitterSeconds)
	loadEnv("KEY_FILE", &idConfig.KeyFile)
	loadEnv("CERT_FILE", &idConfig.CertFile)
	loadEnv("CA_CERT_FILE", &idConfig.CaCertFile)
	loadEnv("INTERMEDIATE_CERT_BUNDLE", &idConfig.IntermediateCertBundle)
	loadEnv("BACKUP", &idConfig.Backup)
	loadEnv("CERT_SECRET", &idConfig.CertSecret)
	loadEnv("NAMESPACE", &idConfig.Namespace)
	loadEnv("ATHENZ_DOMAIN", &idConfig.AthenzDomain)
	loadEnv("ATHENZ_PREFIX", &idConfig.AthenzPrefix)
	loadEnv("ATHENZ_SUFFIX", &idConfig.AthenzSuffix)
	loadEnv("SERVICEACCOUNT", &idConfig.ServiceAccount)
	loadEnv("SA_TOKEN_FILE", &idConfig.SaTokenFile)
	loadEnv("POD_IP", &idConfig.PodIP)
	loadEnv("POD_UID", &idConfig.PodUID)
	loadEnv("SERVER_CA_CERT", &idConfig.ServerCACert)
	loadEnv("TARGET_DOMAIN_ROLES", &idConfig.TargetDomainRoles)
	loadEnv("ROLECERT_DIR", &idConfig.RoleCertDir)
	loadEnv("ROLE_CERT_FILENAME_DELIMITER", &idConfig.RoleCertFilenameDelimiter)
	loadEnv("ROLE_AUTH_HEADER", &idConfig.RoleAuthHeader)
	loadEnv("TOKEN_TYPE", &idConfig.TokenType)
	loadEnv("TOKEN_REFRESH_INTERVAL", &idConfig.rawTokenRefresh)
	loadEnv("TOKEN_SERVER_ADDR", &idConfig.TokenServerAddr)
	loadEnv("TOKEN_DIR", &idConfig.TokenDir)
	loadEnv("METRICS_SERVER_ADDR", &idConfig.MetricsServerAddr)
	loadEnv("DELETE_INSTANCE_ID", &idConfig.rawDeleteInstanceID)

	loadEnv("LOG_DIR", &idConfig.LogDir)
	loadEnv("LOG_LEVEL", &idConfig.LogLevel)

	// file path from ENV is not supported
	// loadEnv("SIDECAR_CONFIG_PATH", &idConfig.rawSidecarConfigPath)

	// TODO: parse values
	// &idConfig.DelayJitterSeconds, _ = strconv.ParseInt(athenz.EnvOrDefault("DELAY_JITTER_SECONDS", "0"), 10, 64)
	// &idConfig.DeleteInstanceID, _ = strconv.ParseBool(athenz.EnvOrDefault("DELETE_INSTANCE_ID", "true"))
	ri, err := time.ParseDuration(refreshInterval)
	if err != nil {
		return fmt.Errorf("Invalid refresh interval [%q], %v", refreshInterval, err)
	}
	tri, err := time.ParseDuration(tokenRefreshInterval)
	if err != nil {
		return fmt.Errorf("Invalid token refresh interval [%q], %v", tokenRefreshInterval, err)
	}
	return nil
}

func (idConfig *IdentityConfig) loadFromFlag(program string, args []string) error {
	f := flag.NewFlagSet(program, flag.ContinueOnError)
	f.StringVar(&idConfig.rawMode, "mode", idConfig.rawMode, "mode, must be one of init or refresh")
	f.StringVar(&idConfig.Endpoint, "endpoint", idConfig.Endpoint, "Athenz ZTS endpoint (required for identity/role certificate and token provisioning)")
	f.StringVar(&idConfig.ProviderService, "provider-service", idConfig.ProviderService, "Identity Provider service (required for identity certificate provisioning)")
	f.StringVar(&idConfig.DNSSuffix, "dns-suffix", idConfig.DNSSuffix, "DNS Suffix for x509 identity/role certificates (required for identity/role certificate provisioning)")
	f.DurationVar(&idConfig.Refresh, "refresh-interval", idConfig.Refresh, "certificate refresh interval")
	f.Int64Var(&idConfig.DelayJitterSeconds, "delay-jitter-seconds", idConfig.DelayJitterSeconds, "delay boot with random jitter within the specified seconds (0 to disable)")
	f.StringVar(&idConfig.KeyFile, "key", idConfig.KeyFile, "key file for the certificate (required)")
	f.StringVar(&idConfig.CertFile, "cert", idConfig.CertFile, "certificate file to identity a service (required)")
	f.StringVar(&idConfig.CaCertFile, "out-ca-cert", idConfig.CaCertFile, "CA certificate file to write")
	f.StringVar(&idConfig.Backup, "backup", idConfig.Backup, "backup certificate to Kubernetes secret (\"read\", \"write\" or \"read+write\", must be run uniquely for each secret to prevent conflict)")
	f.StringVar(&idConfig.CertSecret, "cert-secret", idConfig.CertSecret, "Kubernetes secret name to backup certificate (backup will be disabled with empty)")
	f.StringVar(&idConfig.SaTokenFile, "sa-token-file", idConfig.SaTokenFile, "bound sa jwt token file location (required for identity certificate provisioning)")
	f.StringVar(&idConfig.ServerCACert, "server-ca-cert", idConfig.ServerCACert, "path to CA certificate file to verify ZTS server certs")
	f.StringVar(&idConfig.TargetDomainRoles, "target-domain-roles", idConfig.TargetDomainRoles, "target Athenz roles with domain (e.g. athenz.subdomain"+DEFAULT_ROLE_CERT_FILENAME_DELIMITER+"admin,sys.auth"+DEFAULT_ROLE_CERT_FILENAME_DELIMITER+"providers) (required for role certificate and token provisioning)")
	f.StringVar(&idConfig.RoleCertDir, "rolecert-dir", idConfig.RoleCertDir, "directory to write role certificate files (required for role certificate provisioning)")
	f.StringVar(&idConfig.TokenDir, "token-dir", idConfig.TokenDir, "directory to write token files")
	f.StringVar(&idConfig.TokenType, "token-type", idConfig.TokenType, "type of the role token to request (\"roletoken\", \"accesstoken\" or \"roletoken+accesstoken\")")
	f.DurationVar(&idConfig.TokenRefresh, "token-refresh-interval", idConfig.TokenRefresh, "token refresh interval")
	f.StringVar(&idConfig.TokenServerAddr, "token-server-addr", idConfig.TokenServerAddr, "HTTP server address to provide tokens (required for token provisioning)")
	f.StringVar(&idConfig.MetricsServerAddr, "metrics-server-addr", idConfig.MetricsServerAddr, "HTTP server address to provide metrics")
	f.BoolVar(&idConfig.DeleteInstanceID, "delete-instance-id", idConfig.DeleteInstanceID, "delete x509 certificate record from identity provider when stop signal is sent")
	f.StringVar(&idConfig.LogDir, "log-dir", idConfig.LogDir, "directory to store the log files")
	f.StringVar(&idConfig.LogLevel, "log-level", idConfig.LogLevel, "logging level")
	f.StringVar(&idConfig.rawSidecarConfigPath, "f", idConfig.rawSidecarConfigPath, "config YAML file path")

	var showVersion bool
	f.BoolVar(&showVersion, "version", false, "show version")
	if err := f.Parse(args); err != nil {
		return err
	}
	if showVersion {
		return ErrVersion
	}
	return nil
}

func (idConfig *IdentityConfig) validateAndInit() error {

	if !(idConfig.rawMode == "init" || idConfig.rawMode == "refresh") {
		return fmt.Errorf("Invalid mode [%q] must be one of \"init\" or \"refresh\"", idConfig.rawMode)
	}
	idConfig.Init = idConfig.rawMode == "init"

	pollInterval := idConfig.Refresh
	if pollInterval > util.DefaultPollInterval {
		pollInterval = util.DefaultPollInterval
	}
	pollTokenInterval := idConfig.TokenRefresh
	if pollTokenInterval > DEFAULT_POLL_TOKEN_INTERVAL {
		pollTokenInterval = DEFAULT_POLL_TOKEN_INTERVAL
	}
	reloader, err := util.NewCertReloader(util.ReloadConfig{
		KeyFile:      idConfig.KeyFile,
		CertFile:     idConfig.CertFile,
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
	if idConfig.Init && err == nil && idConfig.ProviderService != "" {
		log.Errorf("SIA(init) detected the existence of X.509 certificate at %s", idConfig.CertFile)
		cert, err := reloader.GetLatestCertificate()
		if err != nil {
			log.Infof("[X.509 Certificate] Subject: %v, DNS SANs: %v, IPs: %v", cert.Leaf.Subject, cert.Leaf.DNSNames, cert.Leaf.IPAddresses)
		}
		log.Infof("Deleting the existing key and cert...")
		if err := os.Remove(idConfig.CertFile); err != nil {
			log.Errorf("Error deleting %s file: %s", idConfig.CertFile, err.Error())
		}
		if err := os.Remove(idConfig.KeyFile); err != nil {
			log.Errorf("Error deleting %s file: %s", idConfig.KeyFile, err.Error())
		}
		return errors.New("Deleted X.509 certificate that already existed.")
	}
	if !idConfig.Init && err != nil {
		return errors.Wrap(err, "unable to read key and cert")
	}

	return nil
}
