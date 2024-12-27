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
	"fmt"
	"net"
	"time"

	"github.com/AthenZ/k8s-athenz-sia/v3/pkg/util"
)

// IdentityConfig from cmd line args
type IdentityConfig struct {
	Init                   bool
	Endpoint               string
	providerService        string
	DNSSuffix              string
	Refresh                time.Duration
	DelayJitterSeconds     int64
	KeyFile                string
	CertFile               string
	CaCertFile             string
	IntermediateCertBundle string
	backup                 string
	certSecret             string
	Namespace              string
	athenzDomain           string
	athenzPrefix           string
	athenzSuffix           string
	ServiceAccount         string
	SaTokenFile            string
	PodIP                  net.IP
	PodUID                 string
	PodName                string
	Reloader               *util.CertReloader
	ServerCACert           string
	K8sSecretBackup        DerivedK8sSecretBackup
	ServiceCert            DerivedServiceCert
	TokenTargetDomainRoles []DomainRole             // TODO: Will be migrated into DerivedTargetDomainRoles
	targetDomainRoles      DerivedTargetDomainRoles // private as the derived state is used only within the config package
	// RoleCerts Derived State and its related fields:
	RoleCert                  DerivedRoleCert
	roleCertDir               string
	roleCertFilenameDelimiter string
	roleCertKeyFileOutput     bool
	roleCertNamingFormat      string
	roleCertKeyNamingFormat   string
	//
	// Token Cache Derived State and its related fields:
	TokenFile                    DerivedTokenFile
	tokenDir                     string
	accessTokenFilenameDelimiter string
	accessTokenNamingFormat      string
	roleTokenFilenameDelimiter   string
	roleTokenNamingFormat        string
	//
	// Token Server Derived State and its related fields:
	TokenServer            DerivedTokenServer
	roleAuthHeader         string
	tokenServerAddr        string
	tokenServerRESTAPI     bool
	tokenServerTimeout     time.Duration
	tokenServerTLSCAPath   string
	tokenServerTLSCertPath string
	tokenServerTLSKeyPath  string
	useTokenServer         bool
	shutdownTimeout        time.Duration
	shutdownDelay          time.Duration
	//
	TokenRefresh        time.Duration
	TokenExpiry         time.Duration
	TokenType           string
	MetricsServerAddr   string
	HealthCheckAddr     string
	HealthCheckEndpoint string
	DeleteInstanceID    bool

	LogDir   string
	LogLevel string

	// raw strings before parsing
	rawMode                  string
	rawPodIP                 string
	rawTargetDomainRoles     string
	rawRefresh               string
	rawDelayJitterSeconds    string
	rawRoleCertKeyFileOutput string
	rawTokenRefresh          string
	rawTokenExpiry           string
	rawTokenServerRESTAPI    string
	rawTokenServerTimeout    string
	rawDeleteInstanceID      string
	rawUseTokenServer        string
	rawShutdownTimeout       string
	rawShutdownDelay         string
}

type DomainRole struct {
	Domain string
	Role   string
}

func (dr DomainRole) String() string {
	return fmt.Sprintf("%s:role.%s", dr.Domain, dr.Role)
}
