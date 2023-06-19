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
}
