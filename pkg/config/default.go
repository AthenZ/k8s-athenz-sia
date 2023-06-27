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
	"fmt"
	"strconv"
	"time"
)

var (
	// default values for X.509 certificate signing request
	DEFAULT_COUNTRY             = "US"
	DEFAULT_PROVINCE            string
	DEFAULT_ORGANIZATION        string
	DEFAULT_ORGANIZATIONAL_UNIT = "Athenz"

	// default values for role tokens and access tokens
	DEFAULT_TOKEN_REFRESH    = 30 * time.Minute
	DEFAULT_TOKEN_EXPIRY_RAW = "0"
	DEFAULT_TOKEN_EXPIRY     = time.Duration(0)

	// DEFAULT_ROLE_CERT_EXPIRY_TIME_BUFFER_MINUTES may be overwritten with go build option (e.g. "-X identity.DEFAULT_ROLE_CERT_EXPIRY_TIME_BUFFER_MINUTES=5")
	DEFAULT_ROLE_CERT_EXPIRY_TIME_BUFFER_MINUTES_RAW = "5"
	DEFAULT_ROLE_CERT_EXPIRY_TIME_BUFFER_MINUTES     = 5

	DEFAULT_ENDPOINT                     string
	DEFAULT_ROLE_AUTH_HEADER             = "Athenz-Role-Auth"
	DEFAULT_DNS_SUFFIX                   = "athenz.cloud"
	DEFAULT_ROLE_CERT_FILENAME_DELIMITER = ":role."
	DEFAULT_INTERMEDIATE_CERT_BUNDLE     string
)

func init() {
	var err error

	// initializes default values from build args
	DEFAULT_TOKEN_EXPIRY, err = time.ParseDuration(DEFAULT_TOKEN_EXPIRY_RAW)
	if err != nil {
		panic(fmt.Errorf("Invalid build flag: DEFAULT_TOKEN_EXPIRY_RAW[%v]", DEFAULT_TOKEN_EXPIRY_RAW))
	}
	DEFAULT_ROLE_CERT_EXPIRY_TIME_BUFFER_MINUTES, err = strconv.Atoi(DEFAULT_ROLE_CERT_EXPIRY_TIME_BUFFER_MINUTES_RAW)
	if err != nil {
		panic(fmt.Errorf("Invalid build flag: DEFAULT_ROLE_CERT_EXPIRY_TIME_BUFFER_MINUTES_RAW[%v]", DEFAULT_ROLE_CERT_EXPIRY_TIME_BUFFER_MINUTES_RAW))
	}
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
		TokenRefresh:              DEFAULT_TOKEN_REFRESH,
		TokenExpiry:               DEFAULT_TOKEN_EXPIRY,
		TokenServerAddr:           "",
		TokenDir:                  "",
		MetricsServerAddr:         "",
		DeleteInstanceID:          true,

		LogDir:   "",
		LogLevel: "INFO",

		rawMode:               "init",
		rawRefresh:            "24h",
		rawDelayJitterSeconds: "0",
		rawTokenRefresh:       DEFAULT_TOKEN_REFRESH.String(),
		rawTokenExpiry:        DEFAULT_TOKEN_EXPIRY.String(),
		rawDeleteInstanceID:   "true",

		Reloader: nil,
	}
}
