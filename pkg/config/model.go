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
// TODO: Move raw out of this Config struct (requires discussion)
type IdentityConfig struct {
	// Core ENVs:
	Init               bool
	Endpoint           string
	Refresh            time.Duration
	DelayJitterSeconds int64
	// TODO: move me to the derived state for kubernetes resource related fields
	podIP          net.IP
	podUID         string
	PodName        string // TODO: To k8s-derived-config
	Namespace      string // TODO: To k8s-derived-config
	saTokenFile    string // TODO: To k8s-derived-config
	certSecret     string // TODO: To k8s-derived-config
	ServiceAccount string // TODO: To k8s-derived-config
	// X509 Configs:
	dnsSuffix              string // TODO: CA.DnsSuffix  OR X509.DnsSuffix
	caCertFile             string // TODO: CA.Cert       OR X509.CaCert
	intermediateCertBundle string // TODO: CA.Bundle     OR X509.CertBundle
	ServerCACert           string // TODO: CA.ServerCert OR X509.ServerCaCert
	// ServiceCert Derived State and its related fields:
	ServiceCert            DerivedServiceCert
	providerService        string
	keyFile                string
	certFile               string
	backup                 string
	athenzDomain           string
	athenzPrefix           string
	athenzSuffix           string
	Reloader               *util.CertReloader
	TokenTargetDomainRoles []DomainRole             // TODO: Will be migrated into DerivedTargetDomainRoles
	targetDomainRoles      DerivedTargetDomainRoles // private as the derived state is used only within the config package
	// RoleCerts Derived State and its related fields:
	RoleCert                  DerivedRoleCert
	roleCertDir               string
	roleCertFilenameDelimiter string
	roleCertKeyFileOutput     bool
	//
	RoleAuthHeader         string
	TokenType              string
	TokenRefresh           time.Duration
	TokenExpiry            time.Duration
	TokenServerAddr        string
	TokenServerRESTAPI     bool
	TokenServerTimeout     time.Duration
	TokenServerTLSCAPath   string
	TokenServerTLSCertPath string
	TokenServerTLSKeyPath  string
	TokenDir               string
	MetricsServerAddr      string
	HealthCheckAddr        string
	HealthCheckEndpoint    string
	DeleteInstanceID       bool
	UseTokenServer         bool
	ShutdownTimeout        time.Duration
	ShutdownDelay          time.Duration

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
