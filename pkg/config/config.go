// Copyright 2023 Yahoo Japan Corporation
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
	"flag"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/pkg/errors"

	athenz "github.com/AthenZ/athenz/libs/go/sia/util"
	"github.com/AthenZ/k8s-athenz-sia/v3/third_party/log"
	"github.com/AthenZ/k8s-athenz-sia/v3/third_party/util"
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
	idConfig := DefaultIdentityConfig()
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
	loadEnv("TOKEN_EXPIRY", &idConfig.rawTokenExpiry)
	loadEnv("TOKEN_SERVER_ADDR", &idConfig.TokenServerAddr)
	loadEnv("TOKEN_SERVER_API_ENABLE", &idConfig.rawTokenServerAPIEnable)
	loadEnv("TOKEN_DIR", &idConfig.TokenDir)
	loadEnv("METRICS_SERVER_ADDR", &idConfig.MetricsServerAddr)
	loadEnv("DELETE_INSTANCE_ID", &idConfig.rawDeleteInstanceID)

	loadEnv("LOG_DIR", &idConfig.LogDir)
	loadEnv("LOG_LEVEL", &idConfig.LogLevel)

	// parse values
	var err error
	idConfig.Init, err = parseMode(idConfig.rawMode)
	if err != nil {
		return fmt.Errorf("Invalid MODE [%q], %v", idConfig.rawMode, err)
	}
	idConfig.Refresh, err = time.ParseDuration(idConfig.rawRefresh)
	if err != nil {
		return fmt.Errorf("Invalid REFRESH_INTERVAL [%q], %v", idConfig.rawRefresh, err)
	}
	idConfig.DelayJitterSeconds, err = strconv.ParseInt(idConfig.rawDelayJitterSeconds, 10, 64)
	if err != nil {
		return fmt.Errorf("Invalid DELAY_JITTER_SECONDS [%q], %v", idConfig.rawDelayJitterSeconds, err)
	}
	idConfig.TokenRefresh, err = time.ParseDuration(idConfig.rawTokenRefresh)
	if err != nil {
		return fmt.Errorf("Invalid TOKEN_REFRESH_INTERVAL [%q], %v", idConfig.rawTokenRefresh, err)
	}
	idConfig.TokenExpiry, err = time.ParseDuration(idConfig.rawTokenExpiry)
	if err != nil {
		return fmt.Errorf("Invalid TOKEN_EXPIRY [%q], %v", idConfig.rawTokenExpiry, err)
	}
	idConfig.TokenServerAPIEnable, err = strconv.ParseBool(idConfig.rawTokenServerAPIEnable)
	if err != nil {
		return fmt.Errorf("Invalid TOKEN_SERVER_API_ENABLE [%q], %v", idConfig.rawTokenServerAPIEnable, err)
	}
	idConfig.DeleteInstanceID, err = strconv.ParseBool(idConfig.rawDeleteInstanceID)
	if err != nil {
		return fmt.Errorf("Invalid DELETE_INSTANCE_ID [%q], %v", idConfig.rawDeleteInstanceID, err)
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
	// IntermediateCertBundle
	f.StringVar(&idConfig.Backup, "backup", idConfig.Backup, "backup certificate to Kubernetes secret (\"read\", \"write\" or \"read+write\", must be run uniquely for each secret to prevent conflict)")
	f.StringVar(&idConfig.CertSecret, "cert-secret", idConfig.CertSecret, "Kubernetes secret name to backup certificate (backup will be disabled with empty)")
	// Namespace
	// AthenzDomain
	// AthenzPrefix
	// AthenzSuffix
	// ServiceAccount
	f.StringVar(&idConfig.SaTokenFile, "sa-token-file", idConfig.SaTokenFile, "bound sa jwt token file location (required for identity certificate provisioning)")
	// PodIP
	// PodUID
	f.StringVar(&idConfig.ServerCACert, "server-ca-cert", idConfig.ServerCACert, "path to CA certificate file to verify ZTS server certs")
	f.StringVar(&idConfig.TargetDomainRoles, "target-domain-roles", idConfig.TargetDomainRoles, "target Athenz roles with domain (e.g. athenz.subdomain"+idConfig.RoleCertFilenameDelimiter+"admin,sys.auth"+idConfig.RoleCertFilenameDelimiter+"providers) (required for role certificate and token provisioning)")
	f.StringVar(&idConfig.RoleCertDir, "rolecert-dir", idConfig.RoleCertDir, "directory to write role certificate files (required for role certificate provisioning)")
	// RoleCertFilenameDelimiter
	// RoleAuthHeader
	f.StringVar(&idConfig.TokenType, "token-type", idConfig.TokenType, "type of the role token to request (\"roletoken\", \"accesstoken\" or \"roletoken+accesstoken\")")
	f.DurationVar(&idConfig.TokenRefresh, "token-refresh-interval", idConfig.TokenRefresh, "token refresh interval")
	f.DurationVar(&idConfig.TokenExpiry, "token-expiry", idConfig.TokenExpiry, "token expiry duration")
	f.StringVar(&idConfig.TokenServerAddr, "token-server-addr", idConfig.TokenServerAddr, "HTTP server address to provide tokens (required for token provisioning)")
	f.BoolVar(&idConfig.TokenServerAPIEnable, "token-server-api-enable", idConfig.TokenServerAPIEnable, "Enable token server RESTful API")
	f.StringVar(&idConfig.TokenDir, "token-dir", idConfig.TokenDir, "directory to write token files")
	f.StringVar(&idConfig.MetricsServerAddr, "metrics-server-addr", idConfig.MetricsServerAddr, "HTTP server address to provide metrics")
	f.BoolVar(&idConfig.DeleteInstanceID, "delete-instance-id", idConfig.DeleteInstanceID, "delete x509 certificate record from identity provider when stop signal is sent")
	// log
	f.StringVar(&idConfig.LogDir, "log-dir", idConfig.LogDir, "directory to store the log files")
	f.StringVar(&idConfig.LogLevel, "log-level", idConfig.LogLevel, "logging level")

	if err := f.Parse(args); err != nil {
		return err
	}

	// parse values
	var err error
	idConfig.Init, err = parseMode(idConfig.rawMode)
	if err != nil {
		return fmt.Errorf("Invalid mode [%q], %v", idConfig.rawMode, err)
	}
	return nil
}

func (idConfig *IdentityConfig) validateAndInit() error {

	if idConfig.TokenExpiry != 0 && idConfig.TokenRefresh >= idConfig.TokenExpiry {
		return fmt.Errorf("Invalid TokenRefresh[%s] >= TokenExpiry[%s]", idConfig.TokenRefresh.String(), idConfig.TokenExpiry.String())
	}

	// TODO: clarify unused logic
	// pollTokenInterval := idConfig.TokenRefresh
	// if pollTokenInterval > DEFAULT_POLL_TOKEN_INTERVAL {
	// 	pollTokenInterval = DEFAULT_POLL_TOKEN_INTERVAL
	// }

	pollInterval := idConfig.Refresh
	if pollInterval > util.DefaultPollInterval {
		pollInterval = util.DefaultPollInterval
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

func parseMode(raw string) (bool, error) {
	if !(raw == "init" || raw == "refresh") {
		return false, fmt.Errorf(`must be one of "init" or "refresh"`)
	}
	return raw == "init", nil
}
