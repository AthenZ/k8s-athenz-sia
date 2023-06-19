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
	"time"

	"github.com/AthenZ/k8s-athenz-sia/v3/third_party/util"
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
	TokenExpiry               time.Duration
	TokenServerAddr           string
	TokenServerAPIEnable      bool
	TokenDir                  string
	MetricsServerAddr         string
	DeleteInstanceID          bool

	LogDir   string
	LogLevel string

	// raw strings before parsing
	rawMode                 string
	rawRefresh              string
	rawDelayJitterSeconds   string
	rawTokenRefresh         string
	rawTokenExpiry          string
	rawTokenServerAPIEnable string
	rawDeleteInstanceID     string
}
