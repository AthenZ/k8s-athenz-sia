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
	"strconv"
	"time"
)

const (
	DEFAULT_SIDECAR_CONFIG_PATH = "/etc/athenz/client/config.yaml"
)

var (
	// default values for X.509 certificate signing request
	DEFAULT_COUNTRY             = "US"
	DEFAULT_PROVINCE            string
	DEFAULT_ORGANIZATION        string
	DEFAULT_ORGANIZATIONAL_UNIT = "Athenz"

	DEFAULT_POLL_TOKEN_INTERVAL = 4 * time.Hour

	// default values for role tokens and access tokens
	DEFAULT_TOKEN_EXPIRY_TIME     = "120"
	DEFAULT_TOKEN_EXPIRY_TIME_INT int

	// DEFAULT_ROLE_CERT_EXPIRY_TIME_BUFFER_MINUTES may be overwritten with go build option (e.g. "-X identity.DEFAULT_ROLE_CERT_EXPIRY_TIME_BUFFER_MINUTES=5")
	DEFAULT_ROLE_CERT_EXPIRY_TIME_BUFFER_MINUTES     = "5"
	DEFAULT_ROLE_CERT_EXPIRY_TIME_BUFFER_MINUTES_INT int

	DEFAULT_ENDPOINT                     string
	DEFAULT_ROLE_AUTH_HEADER             = "Athenz-Role-Auth"
	DEFAULT_DNS_SUFFIX                   = "athenz.cloud"
	DEFAULT_ROLE_CERT_FILENAME_DELIMITER = ":role."
	DEFAULT_INTERMEDIATE_CERT_BUNDLE     string
)

func init() {
	// initializes default values from build args
	DEFAULT_ROLE_CERT_EXPIRY_TIME_BUFFER_MINUTES_INT, _ = strconv.Atoi(DEFAULT_ROLE_CERT_EXPIRY_TIME_BUFFER_MINUTES)
	DEFAULT_TOKEN_EXPIRY_TIME_INT, _ = strconv.Atoi(DEFAULT_TOKEN_EXPIRY_TIME)
}

func DefaultIdentityConfig() *IdentityConfig {
	return &IdentityConfig{
		Init:                      true,
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
