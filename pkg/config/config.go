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

package config

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	athenz "github.com/AthenZ/athenz/libs/go/sia/util"
	"github.com/AthenZ/k8s-athenz-sia/v3/pkg/util"
	"github.com/AthenZ/k8s-athenz-sia/v3/third_party/log"
)

var ErrHelp = flag.ErrHelp
var ErrVersion = errors.New("flag: version requested")

// LoadConfig reads from ENV and args, and then returns an IdentityConfig object (precedence: args > ENV > default).
func LoadConfig(program string, args []string) (*IdentityConfig, error) {

	// show version
	if len(args) == 1 && args[0] == "version" {
		return nil, ErrVersion
	}

	// load with reverse precedence order
	idCfg := DefaultIdentityConfig()
	if err := idCfg.loadFromENV(); err != nil {
		return nil, err
	}
	if err := idCfg.loadFromFlag(program, args); err != nil {
		return nil, err
	}

	// parse custom values that shared by ENV and args to prevent duplicated warnings
	if err := idCfg.parseRawValues(); err != nil {
		return nil, err
	}

	// check fatal errors that startup should be stopped
	if err := idCfg.validateAndInit(); err != nil {
		return nil, err
	}
	return idCfg, nil
}

func (idCfg *IdentityConfig) loadFromENV() error {
	loadEnv := func(envName string, valuePtr *string) {
		*valuePtr = athenz.EnvOrDefault(envName, *valuePtr)
	}

	loadEnv("MODE", &idCfg.rawMode)
	loadEnv("ENDPOINT", &idCfg.Endpoint)
	loadEnv("PROVIDER_SERVICE", &idCfg.ProviderService)
	loadEnv("DNS_SUFFIX", &idCfg.DNSSuffix)
	loadEnv("REFRESH_INTERVAL", &idCfg.rawRefresh)
	loadEnv("DELAY_JITTER_SECONDS", &idCfg.rawDelayJitterSeconds)
	loadEnv("KEY_FILE", &idCfg.KeyFile)
	loadEnv("CERT_FILE", &idCfg.CertFile)
	loadEnv("CA_CERT_FILE", &idCfg.CaCertFile)
	loadEnv("INTERMEDIATE_CERT_BUNDLE", &idCfg.IntermediateCertBundle)
	loadEnv("BACKUP", &idCfg.Backup)
	loadEnv("CERT_SECRET", &idCfg.CertSecret)
	loadEnv("NAMESPACE", &idCfg.Namespace)
	loadEnv("ATHENZ_DOMAIN", &idCfg.AthenzDomain)
	loadEnv("ATHENZ_PREFIX", &idCfg.AthenzPrefix)
	loadEnv("ATHENZ_SUFFIX", &idCfg.AthenzSuffix)
	loadEnv("SERVICEACCOUNT", &idCfg.ServiceAccount)
	loadEnv("SA_TOKEN_FILE", &idCfg.SaTokenFile)
	loadEnv("POD_IP", &idCfg.rawPodIP)
	loadEnv("POD_UID", &idCfg.PodUID)
	loadEnv("POD_NAME", &idCfg.PodName)
	loadEnv("SERVER_CA_CERT", &idCfg.ServerCACert)
	loadEnv("TARGET_DOMAIN_ROLES", &idCfg.rawTargetDomainRoles)
	loadEnv("ROLECERT_DIR", &idCfg.RoleCertDir)
	loadEnv("ROLE_CERT_FILENAME_DELIMITER", &idCfg.RoleCertFilenameDelimiter)
	loadEnv("ROLE_CERT_KEY_FILE_OUTPUT", &idCfg.rawRoleCertKeyFileOutput)
	loadEnv("ROLE_AUTH_HEADER", &idCfg.RoleAuthHeader)
	loadEnv("TOKEN_TYPE", &idCfg.TokenType)
	loadEnv("TOKEN_REFRESH_INTERVAL", &idCfg.rawTokenRefresh)
	loadEnv("TOKEN_EXPIRY", &idCfg.rawTokenExpiry)
	loadEnv("TOKEN_SERVER_ADDR", &idCfg.TokenServerAddr)
	loadEnv("TOKEN_SERVER_REST_API", &idCfg.rawTokenServerRESTAPI)
	loadEnv("TOKEN_SERVER_TIMEOUT", &idCfg.rawTokenServerTimeout)
	loadEnv("TOKEN_SERVER_TLS_CA_PATH", &idCfg.TokenServerTLSCAPath)
	loadEnv("TOKEN_SERVER_TLS_CERT_PATH", &idCfg.TokenServerTLSCertPath)
	loadEnv("TOKEN_SERVER_TLS_KEY_PATH", &idCfg.TokenServerTLSKeyPath)
	loadEnv("TOKEN_DIR", &idCfg.TokenDir)
	loadEnv("METRICS_SERVER_ADDR", &idCfg.MetricsServerAddr)
	loadEnv("DELETE_INSTANCE_ID", &idCfg.rawDeleteInstanceID)
	loadEnv("USE_TOKEN_SERVER", &idCfg.rawUseTokenServer)

	loadEnv("LOG_DIR", &idCfg.LogDir)
	loadEnv("LOG_LEVEL", &idCfg.LogLevel)

	loadEnv("HEALTH_CHECK_ADDR", &idCfg.HealthCheckAddr)
	loadEnv("HEALTH_CHECK_ENDPOINT", &idCfg.HealthCheckEndpoint)

	loadEnv("SHUTDOWN_TIMEOUT", &idCfg.rawShutdownTimeout)
	loadEnv("SHUTDOWN_DELAY", &idCfg.rawShutdownDelay)

	// parse values
	var err error
	if idCfg.rawPodIP != "" {
		idCfg.PodIP = net.ParseIP(idCfg.rawPodIP)
	}
	idCfg.Refresh, err = time.ParseDuration(idCfg.rawRefresh)
	if err != nil {
		return fmt.Errorf("Invalid REFRESH_INTERVAL [%q], %w", idCfg.rawRefresh, err)
	}
	idCfg.DelayJitterSeconds, err = strconv.ParseInt(idCfg.rawDelayJitterSeconds, 10, 64)
	if err != nil {
		return fmt.Errorf("Invalid DELAY_JITTER_SECONDS [%q], %w", idCfg.rawDelayJitterSeconds, err)
	}
	idCfg.RoleCertKeyFileOutput, err = strconv.ParseBool(idCfg.rawRoleCertKeyFileOutput)
	if err != nil {
		return fmt.Errorf("Invalid ROLE_CERT_OUTPUT_KEY_FILE [%q], %w", idCfg.rawRoleCertKeyFileOutput, err)
	}
	idCfg.TokenRefresh, err = time.ParseDuration(idCfg.rawTokenRefresh)
	if err != nil {
		return fmt.Errorf("Invalid TOKEN_REFRESH_INTERVAL [%q], %w", idCfg.rawTokenRefresh, err)
	}
	idCfg.TokenExpiry, err = time.ParseDuration(idCfg.rawTokenExpiry)
	if err != nil {
		return fmt.Errorf("Invalid TOKEN_EXPIRY [%q], %w", idCfg.rawTokenExpiry, err)
	}
	idCfg.TokenServerRESTAPI, err = strconv.ParseBool(idCfg.rawTokenServerRESTAPI)
	if err != nil {
		return fmt.Errorf("Invalid TOKEN_SERVER_REST_API [%q], %w", idCfg.rawTokenServerRESTAPI, err)
	}
	idCfg.TokenServerTimeout, err = time.ParseDuration(idCfg.rawTokenServerTimeout)
	if err != nil {
		return fmt.Errorf("Invalid TOKEN_SERVER_TIMEOUT [%q], %w", idCfg.rawTokenServerTimeout, err)
	}
	idCfg.DeleteInstanceID, err = strconv.ParseBool(idCfg.rawDeleteInstanceID)
	if err != nil {
		return fmt.Errorf("Invalid DELETE_INSTANCE_ID [%q], %w", idCfg.rawDeleteInstanceID, err)
	}
	idCfg.UseTokenServer, err = strconv.ParseBool(idCfg.rawUseTokenServer)
	if err != nil {
		return fmt.Errorf("Invalid USE_TOKEN_SERVER [%q], %w", idCfg.rawUseTokenServer, err)
	}
	idCfg.ShutdownTimeout, err = time.ParseDuration(idCfg.rawShutdownTimeout)
	if err != nil {
		return fmt.Errorf("Invalid SHUTDOWN_TIMEOUT [%q], %w", idCfg.rawShutdownTimeout, err)
	}
	idCfg.ShutdownDelay, err = time.ParseDuration(idCfg.rawShutdownDelay)
	if err != nil {
		return fmt.Errorf("Invalid SHUTDOWN_DELAY [%q], %w", idCfg.rawShutdownDelay, err)
	}
	return nil
}

func (idCfg *IdentityConfig) loadFromFlag(program string, args []string) error {
	f := flag.NewFlagSet(program, flag.ContinueOnError)

	f.StringVar(&idCfg.rawMode, "mode", idCfg.rawMode, "mode, must be one of init or refresh")
	f.StringVar(&idCfg.Endpoint, "endpoint", idCfg.Endpoint, "Athenz ZTS endpoint (required for identity/role certificate and token provisioning)")
	f.StringVar(&idCfg.ProviderService, "provider-service", idCfg.ProviderService, "Identity Provider service (required for identity certificate provisioning)")
	f.StringVar(&idCfg.DNSSuffix, "dns-suffix", idCfg.DNSSuffix, "DNS Suffix for x509 identity/role certificates (required for identity/role certificate provisioning)")
	f.DurationVar(&idCfg.Refresh, "refresh-interval", idCfg.Refresh, "certificate refresh interval")
	f.Int64Var(&idCfg.DelayJitterSeconds, "delay-jitter-seconds", idCfg.DelayJitterSeconds, "delay boot with random jitter within the specified seconds (0 to disable)")
	f.StringVar(&idCfg.KeyFile, "key", idCfg.KeyFile, "key file for the certificate (required)")
	f.StringVar(&idCfg.CertFile, "cert", idCfg.CertFile, "certificate file to identity a service (required)")
	f.StringVar(&idCfg.CaCertFile, "out-ca-cert", idCfg.CaCertFile, "CA certificate file to write")
	// IntermediateCertBundle
	f.StringVar(&idCfg.Backup, "backup", idCfg.Backup, "backup certificate to Kubernetes secret (\"\", \"read\", \"write\" or \"read+write\" must be run uniquely for each secret to prevent conflict)")
	f.StringVar(&idCfg.CertSecret, "cert-secret", idCfg.CertSecret, "Kubernetes secret name to backup certificate (backup will be disabled with empty)")
	// Namespace
	// AthenzDomain
	// AthenzPrefix
	// AthenzSuffix
	// ServiceAccount
	f.StringVar(&idCfg.SaTokenFile, "sa-token-file", idCfg.SaTokenFile, "bound sa jwt token file location (required for identity certificate provisioning)")
	// PodIP
	// PodUID
	f.StringVar(&idCfg.ServerCACert, "server-ca-cert", idCfg.ServerCACert, "path to CA certificate file to verify ZTS server certs")
	f.StringVar(&idCfg.rawTargetDomainRoles, "target-domain-roles", idCfg.rawTargetDomainRoles, "target Athenz roles with domain (e.g. athenz.subdomain"+idCfg.RoleCertFilenameDelimiter+"admin,sys.auth"+idCfg.RoleCertFilenameDelimiter+"providers) (required for role certificate and token provisioning)")
	f.StringVar(&idCfg.RoleCertDir, "rolecert-dir", idCfg.RoleCertDir, "directory to write role certificate files (required for role certificate provisioning)")
	// RoleCertFilenameDelimiter
	f.BoolVar(&idCfg.RoleCertKeyFileOutput, "rolecert-key-file-output", idCfg.RoleCertKeyFileOutput, "output role certificate key file (true/false)")
	// RoleAuthHeader
	f.StringVar(&idCfg.TokenType, "token-type", idCfg.TokenType, "type of the role token to request (\"roletoken\", \"accesstoken\" or \"roletoken+accesstoken\")")
	f.DurationVar(&idCfg.TokenRefresh, "token-refresh-interval", idCfg.TokenRefresh, "token refresh interval")
	f.DurationVar(&idCfg.TokenExpiry, "token-expiry", idCfg.TokenExpiry, "token expiry duration (0 to use Athenz server's default expiry)")
	f.StringVar(&idCfg.TokenServerAddr, "token-server-addr", idCfg.TokenServerAddr, "HTTP server address to provide tokens (required for token provisioning)")
	f.BoolVar(&idCfg.TokenServerRESTAPI, "token-server-rest-api", idCfg.TokenServerRESTAPI, "enable token server RESTful API (true/false)")
	f.DurationVar(&idCfg.TokenServerTimeout, "token-server-timeout", idCfg.TokenServerTimeout, "token server timeout (default 3s)")
	f.StringVar(&idCfg.TokenServerTLSCAPath, "token-server-tls-ca-path", idCfg.TokenServerTLSCAPath, "token server TLS CA path (if set, enable TLS Client Authentication)")
	f.StringVar(&idCfg.TokenServerTLSCertPath, "token-server-tls-cert-path", idCfg.TokenServerTLSCertPath, "token server TLS certificate path (if empty, disable TLS)")
	f.StringVar(&idCfg.TokenServerTLSKeyPath, "token-server-tls-key-path", idCfg.TokenServerTLSKeyPath, "token server TLS certificate key path (if empty, disable TLS)")
	f.StringVar(&idCfg.TokenDir, "token-dir", idCfg.TokenDir, "directory to write token files")
	f.StringVar(&idCfg.MetricsServerAddr, "metrics-server-addr", idCfg.MetricsServerAddr, "HTTP server address to provide metrics")
	f.BoolVar(&idCfg.DeleteInstanceID, "delete-instance-id", idCfg.DeleteInstanceID, "delete x509 certificate record from identity provider on shutdown (true/false)")
	// Token Server
	f.BoolVar(&idCfg.UseTokenServer, "use-token-server", idCfg.UseTokenServer, "enable token server (true/false)")
	// log
	f.StringVar(&idCfg.LogDir, "log-dir", idCfg.LogDir, "directory to store the log files")
	f.StringVar(&idCfg.LogLevel, "log-level", idCfg.LogLevel, "logging level")
	// healthCheck
	f.StringVar(&idCfg.HealthCheckAddr, "health-check-addr", idCfg.HealthCheckAddr, "HTTP server address to provide health check")
	f.StringVar(&idCfg.HealthCheckEndpoint, "health-check-endpoint", idCfg.HealthCheckEndpoint, "HTTP server endpoint to provide health check")
	// graceful shutdown option
	f.DurationVar(&idCfg.ShutdownTimeout, "shutdown-timeout", idCfg.ShutdownTimeout, "graceful shutdown timeout")
	f.DurationVar(&idCfg.ShutdownDelay, "shutdown-delay", idCfg.ShutdownDelay, "graceful shutdown delay")
	if err := f.Parse(args); err != nil {
		return err
	}

	return nil
}

func (idCfg *IdentityConfig) parseRawValues() (err error) {
	idCfg.Init, err = parseMode(idCfg.rawMode)
	if err != nil {
		return fmt.Errorf("Invalid MODE/mode [%q], %w", idCfg.rawMode, err)
	}

	if idCfg.rawTargetDomainRoles != "" {
		idCfg.TargetDomainRoles, err = parseTargetDomainRoles(idCfg.rawTargetDomainRoles)
		if err != nil {
			// continue if partially valid, fail if nothing valid
			log.Warnf("Invalid TARGET_DOMAIN_ROLES/target-domain-roles [%q], warnings:\n%s", idCfg.rawTargetDomainRoles, err.Error())
			if len(idCfg.TargetDomainRoles) == 0 {
				return fmt.Errorf("Invalid TARGET_DOMAIN_ROLES [%q], %w", idCfg.rawTargetDomainRoles, fmt.Errorf("NO valid domain-role pairs"))
			}
			// reset warnings
			err = nil
		}
	}

	return err
}

func (idCfg *IdentityConfig) validateAndInit() (err error) {

	if idCfg.TokenExpiry != 0 && idCfg.TokenRefresh >= idCfg.TokenExpiry {
		return fmt.Errorf("Invalid TokenRefresh[%s] >= TokenExpiry[%s]", idCfg.TokenRefresh.String(), idCfg.TokenExpiry.String())
	}

	// TODO: clarify unused logic
	// pollTokenInterval := idCfg.TokenRefresh
	// if pollTokenInterval > DEFAULT_POLL_TOKEN_INTERVAL {
	// 	pollTokenInterval = DEFAULT_POLL_TOKEN_INTERVAL
	// }

	pollInterval := idCfg.Refresh
	if pollInterval > util.DefaultPollInterval {
		pollInterval = util.DefaultPollInterval
	}
	idCfg.Reloader, err = util.NewCertReloader(util.ReloadConfig{
		Init:            idCfg.Init,
		ProviderService: idCfg.ProviderService,
		KeyFile:         idCfg.KeyFile,
		CertFile:        idCfg.CertFile,
		Logger:          log.Debugf,
		PollInterval:    pollInterval,
	})

	// if certificate provisioning is disabled (use external key) and splitting role certificate key file is disabled, role certificate and external key mismatch problem may occur when external key rotates.
	// error case: issue role certificate, rotate external key, mismatch period, issue role certificate, resolve, rotate external key, ...
	if idCfg.ProviderService == "" && !idCfg.RoleCertKeyFileOutput {
		// if role certificate issuing is enabled, warn user about the mismatch problem
		if idCfg.rawTargetDomainRoles != "" && idCfg.RoleCertDir != "" {
			log.Warnf("Rotating KEY_FILE[%s] may cause key mismatch with issued role certificate due to different rotation cycle. Please manually restart SIA when you rotate the key file.", idCfg.KeyFile)
		}
	}

	// During the init flow if X.509 cert(and key) already exists,
	//   - someone is attempting to run init after a pod has been started
	//   - pod sandbox crashed and kubelet runs the init container
	// SIA does not have enough information to differentiate between the two situations.
	// The idea is to delegate the decision to re-issue the X.509 certificate to the identity provider
	// In the case when the podIP changes after a pod sandbox crash, the new pod IP might not have propagated yet
	// to the kube and kubelet APIs. So, we might end up getting an X.509 certificate with the old pod IP.
	// To avoid this, we fail the current run with an error to force SYNC the status on the pod resource and let
	// the subsequent retry for the init container to attempt to get a new certificate from the identity provider.
	if idCfg.Init && err == nil && idCfg.ProviderService != "" {
		log.Errorf("SIA(init) detected the existence of X.509 certificate at %s", idCfg.CertFile)
		cert, err := idCfg.Reloader.GetLatestCertificate()
		if err != nil {
			log.Infof("[X.509 Certificate] Subject: %v, DNS SANs: %v, IPs: %v", cert.Leaf.Subject, cert.Leaf.DNSNames, cert.Leaf.IPAddresses)
		}
		log.Infof("Deleting the existing key and cert...")
		if err := os.Remove(idCfg.CertFile); err != nil {
			log.Errorf("Error deleting %s file: %s", idCfg.CertFile, err.Error())
		}
		if err := os.Remove(idCfg.KeyFile); err != nil {
			log.Errorf("Error deleting %s file: %s", idCfg.KeyFile, err.Error())
		}
		return errors.New("Deleted X.509 certificate that already existed.")
	}
	if !idCfg.Init && err != nil {
		return fmt.Errorf("Unable to read key and cert: %w", err)
	}

	return nil
}

func parseMode(raw string) (bool, error) {
	if !(raw == "init" || raw == "refresh") {
		return false, fmt.Errorf(`must be one of "init" or "refresh"`)
	}
	return raw == "init", nil
}

func parseTargetDomainRoles(raw string) ([]DomainRole, error) {
	elements := strings.Split(raw, ",")
	errs := make([]error, 0, len(elements))
	domainRoles := make([]DomainRole, 0, len(elements))

	for _, domainRole := range elements {
		targetDomain, targetRole, err := athenz.SplitRoleName(domainRole)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to read target domain and role from element: [%q], err: %w", domainRole, err))
			continue
		}
		domainRoles = append(domainRoles, DomainRole{
			Domain: targetDomain,
			Role:   targetRole,
		})
	}

	return domainRoles, errors.Join(errs...)
}
