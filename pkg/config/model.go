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
	Init                         bool
	Endpoint                     string
	ProviderService              string
	DNSSuffix                    string
	Refresh                      time.Duration
	DelayJitterSeconds           int64
	KeyFile                      string
	CertFile                     string
	CaCertFile                   string
	IntermediateCertBundle       string
	Backup                       string
	CertSecret                   string
	Namespace                    string
	AthenzDomain                 string
	AthenzPrefix                 string
	AthenzSuffix                 string
	ServiceAccount               string
	SaTokenFile                  string
	PodIP                        net.IP
	PodUID                       string
	PodName                      string
	Reloader                     *util.CertReloader
	ServerCACert                 string
	TargetDomainRoles            []DomainRole
	RoleCertDir                  string
	RoleCertFilenameDelimiter    string
	RoleCertKeyFileOutput        bool
	RoleAuthHeader               string
	TokenType                    string
	TokenRefresh                 time.Duration
	TokenExpiry                  time.Duration
	TokenServerAddr              string
	TokenServerRESTAPI           bool
	TokenServerTimeout           time.Duration
	TokenServerTLSCAPath         string
	TokenServerTLSCertPath       string
	TokenServerTLSKeyPath        string
	AccessTokenNamingFormat      string
	AccessTokenFilenameDelimiter string
	RoleTokenNamingFormat        string
	RoleTokenFilenameDelimiter   string
	TokenDir                     string
	MetricsServerAddr            string
	HealthCheckAddr              string
	HealthCheckEndpoint          string
	DeleteInstanceID             bool
	UseTokenServer               bool
	ShutdownTimeout              time.Duration
	ShutdownDelay                time.Duration

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
