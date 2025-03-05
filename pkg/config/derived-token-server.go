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

// Package config defines all the configuration parameters. It reads configuration from environment variables and command-line arguments.
package config

import (
	"strings"
	"time"
)

// HeaderTokenMode is a mode that exchanges information such as domain and role tokens with tenants by attaching it to the request and response headers.
// TODO: Consider whether there is a better name for the struct.
type HeaderTokenMode struct {
	Use            bool
	RoleAuthHeader string
}

// RestAPIMode is a mode that exchanges information such as domain and role tokens with tenants by attaching it to the POST request and response body.
type RestAPIMode struct {
	Use bool
}

// TLS is a struct that summarizes the configuration details for enabling TLS communication between tenants and SIA.
type TLS struct {
	Use      bool
	CAPath   string
	CertPath string
	KeyPath  string
}

type DerivedTokenServer struct {
	Use             bool            // whether to use the token server
	HeaderToken     HeaderTokenMode // header token mode configuration
	RestAPI         RestAPIMode     // rest api mode configuration
	Addr            string          // token server address
	ShutdownDelay   time.Duration   // Shutdown delay for gracefully shutting down the Token Server
	ShutdownTimeout time.Duration   // Shutdown timeout for gracefully shutting down the Token Server
	ServerTimeout   time.Duration   // Timeout for receiving a request from a tenant and sending a response
	TLS             TLS             // TLS configuration for token server
}

// derivedTokenFileConfig reads given configuration and sets the derived state of outputting token file related configuration.
func (idCfg *IdentityConfig) derivedTokenServerConfig() error {
	// default:
	idCfg.TokenServer = DerivedTokenServer{
		Use:             false,
		Addr:            "",
		ShutdownDelay:   0,
		ShutdownTimeout: 0,
		ServerTimeout:   0,
		TLS: TLS{
			Use:      false,
			CAPath:   "",
			CertPath: "",
			KeyPath:  "",
		},
		HeaderToken: HeaderTokenMode{
			Use:            false,
			RoleAuthHeader: "",
		},
		RestAPI: RestAPIMode{
			Use: false,
		},
	}

	if idCfg.Init {
		return nil // disabled
	}
	if idCfg.tokenServerAddr == "" || (!strings.Contains(idCfg.TokenType, "accesstoken") && !strings.Contains(idCfg.TokenType, "roletoken")) {
		return nil // disabled
	}

	// Enable from now on:
	idCfg.TokenServer = DerivedTokenServer{
		Use:             true,
		Addr:            idCfg.tokenServerAddr,
		ShutdownDelay:   idCfg.shutdownDelay,
		ShutdownTimeout: idCfg.shutdownTimeout,
		ServerTimeout:   idCfg.tokenServerTimeout,
		TLS: func() TLS {
			// disabled
			if idCfg.tokenServerTLSCertPath == "" && idCfg.tokenServerTLSKeyPath == "" {
				return TLS{
					Use:      false,
					CAPath:   "",
					CertPath: "",
					KeyPath:  "",
				}
			}
			return TLS{
				Use:      true,
				CAPath:   idCfg.tokenServerTLSCAPath,
				CertPath: idCfg.tokenServerTLSCertPath,
				KeyPath:  idCfg.tokenServerTLSKeyPath,
			}
		}(),
		HeaderToken: func() HeaderTokenMode {
			// disabled
			if !idCfg.useTokenServer {
				return HeaderTokenMode{
					Use:            false,
					RoleAuthHeader: "",
				}
			}
			return HeaderTokenMode{
				Use:            true,
				RoleAuthHeader: idCfg.roleAuthHeader,
			}
		}(),
		RestAPI: func() RestAPIMode {
			// disabled
			if !idCfg.tokenServerRESTAPI {
				return RestAPIMode{
					Use: false,
				}
			}
			return RestAPIMode{
				Use: true,
			}
		}(),
	}

	return nil
}
