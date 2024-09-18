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

type TokenServerMode struct {
	Use            bool
	RoleAuthHeader string
}

type RestAPIMode struct {
	Use bool
}

type TLS struct {
	Use      bool
	CAPath   string
	CertPath string
	KeyPath  string
}

type DerivedTokenServer struct {
	Use             bool
	Addr            string
	ShutdownDelay   time.Duration
	ShutdownTimeout time.Duration
	ServerTimeout   time.Duration
	TLS             TLS
	TokenServer     TokenServerMode
	RestAPI         RestAPIMode
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
		TokenServer: TokenServerMode{
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
			if idCfg.tokenServerTLSCertPath == "" && idCfg.tokenServerTLSKeyPath == "" {
				// disabled
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
		TokenServer: func() TokenServerMode {
			if !idCfg.useTokenServer {
				// disabled
				return TokenServerMode{
					Use:            false,
					RoleAuthHeader: "",
				}
			}
			return TokenServerMode{
				Use:            true,
				RoleAuthHeader: idCfg.roleAuthHeader,
			}
		}(),
		RestAPI: func() RestAPIMode {
			if !idCfg.tokenServerRESTAPI {
				// disabled
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
