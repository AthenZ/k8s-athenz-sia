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
	"strconv"
	"time"
)

var (
	// default values for X.509 certificate signing request
	DEFAULT_COUNTRY             string
	DEFAULT_PROVINCE            string
	DEFAULT_ORGANIZATION        string
	DEFAULT_ORGANIZATIONAL_UNIT = "Athenz"

	// default values for role tokens and access tokens
	DEFAULT_TOKEN_REFRESH        = 30 * time.Minute
	DEFAULT_TOKEN_EXPIRY_RAW     = "0"
	DEFAULT_TOKEN_EXPIRY         = time.Duration(0)
	DEFAULT_TOKEN_SERVER_TIMEOUT = 3 * time.Second

	// DEFAULT_ROLE_CERT_EXPIRY_TIME_BUFFER_MINUTES may be overwritten with go build option (e.g. "-X identity.DEFAULT_ROLE_CERT_EXPIRY_TIME_BUFFER_MINUTES=5")
	DEFAULT_ROLE_CERT_EXPIRY_TIME_BUFFER_MINUTES_RAW = "5"
	DEFAULT_ROLE_CERT_EXPIRY_TIME_BUFFER_MINUTES     = 5

	DEFAULT_ENDPOINT                        string
	DEFAULT_ROLE_AUTH_HEADER                = "Athenz-Role-Auth"
	DEFAULT_DNS_SUFFIX                      = "athenz.cloud"
	DEFAULT_ROLE_CERT_FILENAME_DELIMITER    = ":role."
	DEFAULT_ACCESS_TOKEN_FILENAME_DELIMITER = ":role."
	DEFAULT_ROLE_TOKEN_FILENAME_DELIMITER   = ":role."
	DEFAULT_INTERMEDIATE_CERT_BUNDLE        string

	// default values for graceful shutdown
	DEFAULT_SHUTDOWN_TIMEOUT = 5 * time.Second
	DEFAULT_SHUTDOWN_DELAY   = time.Duration(0)

	// default maximum elapsed time on initialization
	DEFAULT_MAX_ELAPSED_TIME_ON_INIT = 1 * time.Minute
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
		Init:                         true,
		Endpoint:                     DEFAULT_ENDPOINT,
		providerService:              "",
		DNSSuffix:                    DEFAULT_DNS_SUFFIX,
		Refresh:                      24 * time.Hour,
		DelayJitterSeconds:           0,
		KeyFile:                      "",
		CertFile:                     "",
		CaCertFile:                   "",
		IntermediateCertBundle:       DEFAULT_INTERMEDIATE_CERT_BUNDLE,
		backup:                       "",
		certSecret:                   "",
		Namespace:                    "",
		athenzDomain:                 "",
		athenzPrefix:                 "",
		athenzSuffix:                 "",
		ServiceAccount:               "",
		SaTokenFile:                  "",
		PodIP:                        nil,
		PodUID:                       "",
		PodName:                      "",
		Reloader:                     nil,
		ServerCACert:                 "",
		TokenTargetDomainRoles:       []DomainRole{},
		roleCertDir:                  "",
		roleCertFilenameDelimiter:    DEFAULT_ROLE_CERT_FILENAME_DELIMITER,
		roleCertKeyFileOutput:        false,
		roleCertNamingFormat:         "",
		roleCertKeyNamingFormat:      "",
		roleAuthHeader:               DEFAULT_ROLE_AUTH_HEADER,
		TokenType:                    "accesstoken",
		TokenRefresh:                 DEFAULT_TOKEN_REFRESH,
		TokenExpiry:                  DEFAULT_TOKEN_EXPIRY,
		tokenServerAddr:              "",
		tokenServerRESTAPI:           false,
		tokenServerTimeout:           DEFAULT_TOKEN_SERVER_TIMEOUT,
		tokenServerTLSCAPath:         "",
		tokenServerTLSCertPath:       "",
		tokenServerTLSKeyPath:        "",
		tokenDir:                     "",
		accessTokenFilenameDelimiter: DEFAULT_ACCESS_TOKEN_FILENAME_DELIMITER,
		accessTokenNamingFormat:      "",
		roleTokenFilenameDelimiter:   DEFAULT_ROLE_TOKEN_FILENAME_DELIMITER,
		roleTokenNamingFormat:        "",
		MetricsServerAddr:            "",
		HealthCheckAddr:              "",
		HealthCheckEndpoint:          "",
		DeleteInstanceID:             false,
		useTokenServer:               false,
		shutdownTimeout:              DEFAULT_SHUTDOWN_TIMEOUT,
		shutdownDelay:                DEFAULT_SHUTDOWN_DELAY,

		LogDir:   fmt.Sprintf("/var/log/%s", APP_NAME),
		LogLevel: "INFO",

		rawMode:                  "init",
		rawPodIP:                 "",
		rawTargetDomainRoles:     "",
		rawRefresh:               "24h",
		rawDelayJitterSeconds:    "0",
		rawCertExtraSANDNSs:      "",
		rawRoleCertKeyFileOutput: "false",
		rawTokenRefresh:          DEFAULT_TOKEN_REFRESH.String(),
		rawTokenExpiry:           DEFAULT_TOKEN_EXPIRY.String(),
		rawTokenServerRESTAPI:    "false",
		rawTokenServerTimeout:    DEFAULT_TOKEN_SERVER_TIMEOUT.String(),
		rawDeleteInstanceID:      "false",
		rawUseTokenServer:        "false",
		rawShutdownTimeout:       DEFAULT_SHUTDOWN_TIMEOUT.String(),
		rawShutdownDelay:         DEFAULT_SHUTDOWN_DELAY.String(),
	}
}
