package config

import (
	"time"

	"github.com/AthenZ/k8s-athenz-sia/third_party/util"
)

// IdentityConfig from cmd line args
type IdentityConfig struct {
	Init                      bool
	Endpoint                  string
	ProviderService           string
	DNSSuffix                 string
	Refresh                   time.Duration
	DelayJitterSeconds        int64
	KeyFile                   string
	CertFile                  string
	CaCertFile                string
	IntermediateCertBundle    string
	Backup                    string
	CertSecret                string
	Namespace                 string
	AthenzDomain              string
	AthenzPrefix              string
	AthenzSuffix              string
	ServiceAccount            string
	SaTokenFile               string
	PodIP                     string
	PodUID                    string
	Reloader                  *util.CertReloader
	ServerCACert              string
	TargetDomainRoles         string
	RoleCertDir               string
	RoleCertFilenameDelimiter string
	RoleAuthHeader            string
	TokenType                 string
	TokenRefresh              time.Duration
	TokenServerAddr           string
	TokenDir                  string
	MetricsServerAddr         string
	DeleteInstanceID          bool

	LogDir   string
	LogLevel string

	rawMode               string
	rawRefresh            string
	rawDelayJitterSeconds string
	rawTokenRefresh       string
	rawDeleteInstanceID   string
	rawSidecarConfigPath  string
}

func DefaultIdentityConfig() *IdentityConfig {
	return &IdentityConfig{
		Init:                      false,
		Endpoint:                  DEFAULT_ENDPOINT,
		ProviderService:           "",
		DNSSuffix:                 DEFAULT_DNS_SUFFIX,
		Refresh:                   24 * time.Hour,
		DelayJitterSeconds:        0,
		KeyFile:                   "",
		CertFile:                  "",
		CaCertFile:                "",
		IntermediateCertBundle:    DEFAULT_INTERMEDIATE_CERT_BUNDLE,
		Backup:                    "read+write",
		CertSecret:                "",
		Namespace:                 "",
		AthenzDomain:              "",
		AthenzPrefix:              "",
		AthenzSuffix:              "",
		ServiceAccount:            "",
		SaTokenFile:               "",
		PodIP:                     "127.0.0.1",
		PodUID:                    "",
		ServerCACert:              "",
		TargetDomainRoles:         "",
		RoleCertDir:               "",
		RoleCertFilenameDelimiter: DEFAULT_ROLE_CERT_FILENAME_DELIMITER,
		RoleAuthHeader:            DEFAULT_ROLE_AUTH_HEADER,
		TokenType:                 "accesstoken",
		TokenRefresh:              30 * time.Minute,
		TokenServerAddr:           "",
		TokenDir:                  "",
		MetricsServerAddr:         "",
		DeleteInstanceID:          true,

		LogDir:   "",
		LogLevel: "INFO",

		// raw strings before parsing
		rawMode:               "init",
		rawRefresh:            "24h",
		rawDelayJitterSeconds: "0",
		rawTokenRefresh:       "30m",
		rawDeleteInstanceID:   "true",
		rawSidecarConfigPath:  DEFAULT_SIDECAR_CONFIG_PATH,

		Reloader: nil,
	}
}
