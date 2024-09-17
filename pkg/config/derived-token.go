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
	"path/filepath"
	"strings"
	"time"

	"github.com/AthenZ/k8s-athenz-sia/v3/third_party/log"
)

type WriteFileConfig struct {
	Use       bool
	Dir       string // TODO: remove
	Format    string
	Delimiter string
}

type WriteFileMode struct {
	Use         bool
	AccessToken WriteFileConfig
	RoleToken   WriteFileConfig
}

type TLS struct {
	Use  bool
	CA   string
	Cert string
	Key  string
}

type ServerMode struct {
	Use            bool
	UseAccessToken bool
	UseRoleToken   bool

	// common
	TokenServerAddr    string
	ShutdownDelay      time.Duration
	ShutdownTimeout    time.Duration
	TokenServerTimeout time.Duration
	TLS                TLS

	// REST API
	UseRESTAPI bool

	// Token Server
	UseTokenServer bool
	RoleAuthHeader string
}

type DerivedToken struct {
	// TODO: need Use?
	// Use 			   bool
	WriteFile           WriteFileMode
	Server              ServerMode
	TargetDomainRoles   []DomainRole
	TokenRefresh        time.Duration
	TokenExpiryInSecond int
}

// // derivedAccessToken ... TODO: Comment
func (idCfg *IdentityConfig) derivedTokenConfig() error {

	// default:
	idCfg.Token = DerivedToken{
		WriteFile: WriteFileMode{
			Use: false,
			AccessToken: WriteFileConfig{
				Use:       false,
				Format:    "",
				Delimiter: "",
			},
			RoleToken: WriteFileConfig{
				Use:       false,
				Format:    "",
				Delimiter: "",
			},
		},
		Server: ServerMode{
			Use:                false,
			UseAccessToken:     false,
			UseRoleToken:       false,
			TokenServerAddr:    "",
			ShutdownDelay:      0,
			ShutdownTimeout:    0,
			TokenServerTimeout: 0,
			TLS: TLS{
				Use:  false,
				CA:   "",
				Cert: "",
				Key:  "",
			},
			UseRESTAPI:     false,
			UseTokenServer: false,
			RoleAuthHeader: "",
		},
		TokenRefresh:        0,
		TokenExpiryInSecond: 0,
	}

	// write file mode
	if err := idCfg.derivedWriteFileTokenConfig(); err != nil {
		return err
	}

	// server mode
	if err := idCfg.derivedServerTokenConfig(); err != nil {
		return err
	}

	// token refresh
	idCfg.Token.TargetDomainRoles = idCfg.targetDomainRoles.tokens
	idCfg.Token.TokenRefresh = idCfg.tokenRefresh
	idCfg.Token.TokenExpiryInSecond = int(idCfg.tokenExpiry.Seconds())

	return nil
}

func (idCfg *IdentityConfig) derivedWriteFileTokenConfig() error {
	if idCfg.tokenDir == "" {
		return nil // disabled
	}
	// Enable from now on:
	idCfg.Token.WriteFile.Use = true

	// Access Token
	if strings.Contains(idCfg.tokenType, "accesstoken") {
		idCfg.Token.WriteFile.AccessToken = WriteFileConfig{
			Use:       true,
			Dir:       idCfg.tokenDir,
			Format:    filepath.Join(idCfg.tokenDir, "{{domain}}{{delimiter}}{{role}}.accesstoken"),
			Delimiter: ":role.",
		}
	}

	// Role Token
	if strings.Contains(idCfg.tokenType, "roletoken") {
		idCfg.Token.WriteFile.RoleToken = WriteFileConfig{
			Use:       true,
			Dir:       idCfg.tokenDir,
			Format:    filepath.Join(idCfg.tokenDir, "{{domain}}{{delimiter}}{{role}}.roletoken"),
			Delimiter: ":role.",
		}
	}
	return nil
}

func (idCfg *IdentityConfig) derivedServerTokenConfig() error {

	if idCfg.Init {
		log.Infof("Token server is disabled for init mode: address[%s]", idCfg.tokenServerAddr)
		return nil // disabled
	}

	useAccessToken := strings.Contains(idCfg.tokenType, "accesstoken")
	useRoleToken := strings.Contains(idCfg.tokenType, "roletoken")
	if idCfg.tokenServerAddr == "" || (!useAccessToken && !useRoleToken) {
		log.Infof("Token server is disabled due to insufficient options: address[%s], token-type[%s]", idCfg.tokenServerAddr, idCfg.tokenType)
		return nil // disabled
	}

	// Enable from now on:
	idCfg.Token.Server = ServerMode{
		Use:            true,
		UseAccessToken: useAccessToken,
		UseRoleToken:   useRoleToken,

		TokenServerAddr:    idCfg.tokenServerAddr,
		ShutdownDelay:      idCfg.ShutdownDelay,
		ShutdownTimeout:    idCfg.ShutdownTimeout,
		TokenServerTimeout: idCfg.tokenServerTimeout,
		TLS: func() TLS {
			if idCfg.tokenServerTLSCertPath == "" || idCfg.tokenServerTLSKeyPath == "" {
				return TLS{
					Use:  false,
					CA:   "",
					Cert: "",
					Key:  "",
				}
			}
			return TLS{
				Use:  true,
				CA:   idCfg.tokenServerTLSCAPath,
				Cert: idCfg.tokenServerTLSCertPath,
				Key:  idCfg.tokenServerTLSKeyPath,
			}
		}(),
		UseRESTAPI:     idCfg.tokenServerRESTAPI,
		UseTokenServer: idCfg.useTokenServer,
		RoleAuthHeader: idCfg.roleAuthHeader,
	}
	return nil
}
