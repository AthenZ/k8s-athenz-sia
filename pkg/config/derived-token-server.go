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
)

type Tls struct {
	CaPath   string // optional
	CertPath string
	KeyPath  string
}
type DerivedTokenServer struct {
	Use     bool
	Address string // server address i.e) "http://localhost:4443"
	Tls     *Tls   // tls configuration if enabled; nil if disabled
}

// TODO: Use idCfg.targetDomainRoles.TokenTargetDomainRoles

// derivedTokenServerConfig ... // TODO: Comment
func (idCfg *IdentityConfig) derivedTokenServerConfig() error {
	// TODO: Write
	// default (disabled):
	idCfg.TokenServer = DerivedTokenServer{
		Use:     false,
		Address: "",
	}

	if idCfg.Init {
		// log.Infof("Token server is disabled for init mode: address[%s]", idCfg.TokenServerAddr)
		return nil
	}

	if idCfg.tokenServerAddr == "" {
		// log.Infof("Token server is disabled due to insufficient options: address[%s], token-type[%s]", idCfg.TokenServerAddr, idCfg.TokenType)
		return nil
	}

	if !strings.Contains(idCfg.TokenType, "accesstoken") && !strings.Contains(idCfg.TokenType, "roletoken") {
		// log.Infof("Token server is disabled due to insufficient options: address[%s], token-type[%s]", idCfg.TokenServerAddr, idCfg.TokenType)
		return nil
	}

	// Enable from now on:
	idCfg.TokenServer = DerivedTokenServer{
		Use:     true,
		Address: idCfg.tokenServerAddr,
		Tls: func() *Tls {
			if idCfg.tokenServerTLSCertPath == "" || idCfg.tokenServerTLSKeyPath == "" {
				return nil
			}
			return &Tls{
				CaPath:   idCfg.tokenServerTLSCAPath, // optional, can be empty ""
				CertPath: idCfg.tokenServerTLSCertPath,
				KeyPath:  idCfg.tokenServerTLSKeyPath,
			}
		}(),
	}

	return nil
}
