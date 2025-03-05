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
	"fmt"
	"path/filepath"
	"strings"
)

type TokenFileConfig struct {
	Use       bool
	Format    string
	Delimiter string
}

type DerivedTokenFile struct {
	AccessToken TokenFileConfig
	RoleToken   TokenFileConfig
}

// derivedTokenFileConfig reads given configuration and sets the derived state of outputting token file related configuration.
func (idCfg *IdentityConfig) derivedTokenFileConfig() error {
	// default:
	idCfg.TokenFile = DerivedTokenFile{
		AccessToken: TokenFileConfig{
			Use:       false,
			Format:    "",
			Delimiter: "",
		},
		RoleToken: TokenFileConfig{
			Use:       false,
			Format:    "",
			Delimiter: "",
		},
	}

	// TODO: Apply the following instead?:
	// if idCfg.TokenDir == ""  || idCfg.TokenType == "" {
	if idCfg.tokenDir == "" && idCfg.accessTokenNamingFormat == "" && idCfg.roleTokenNamingFormat == "" {
		return nil // disabled
	}

	// If both the TokenDir settings and the NamingFormat settings are configured redundantly, an error will be returned.
	if idCfg.tokenDir != "" && idCfg.accessTokenNamingFormat != "" {
		return fmt.Errorf("Both TOKEN_DIR[%s] and ACCESS_TOKEN_NAMING_FORMAT[%s] are set. Please ensure only one of these is specified to avoid conflicts.", idCfg.tokenDir, idCfg.accessTokenNamingFormat)
	}
	if idCfg.tokenDir != "" && idCfg.roleTokenNamingFormat != "" {
		return fmt.Errorf("Both TOKEN_DIR[%s] and ROLE_TOKEN_NAMING_FORMAT[%s] are set. Please ensure only one of these is specified to avoid conflicts.", idCfg.tokenDir, idCfg.roleTokenNamingFormat)

	}

	// Enable from now on:
	idCfg.TokenFile = DerivedTokenFile{
		AccessToken: func() TokenFileConfig {
			// disabled
			if !strings.Contains(idCfg.TokenType, "accesstoken") {
				return TokenFileConfig{
					Use:       false,
					Format:    "",
					Delimiter: "",
				}
			}
			if idCfg.accessTokenNamingFormat != "" {
				return TokenFileConfig{
					Use:       true,
					Format:    idCfg.accessTokenNamingFormat,
					Delimiter: idCfg.accessTokenFilenameDelimiter,
				}
			}
			return TokenFileConfig{
				Use:       true,
				Format:    filepath.Join(idCfg.tokenDir, "{{domain}}{{delimiter}}{{role}}.accesstoken"),
				Delimiter: idCfg.accessTokenFilenameDelimiter,
			}

		}(),
		RoleToken: func() TokenFileConfig {
			// disabled
			if !strings.Contains(idCfg.TokenType, "roletoken") {
				return TokenFileConfig{
					Use:       false,
					Format:    "",
					Delimiter: "",
				}
			}
			if idCfg.roleTokenNamingFormat != "" {
				return TokenFileConfig{
					Use:       true,
					Format:    idCfg.roleTokenNamingFormat,
					Delimiter: idCfg.roleTokenFilenameDelimiter,
				}
			}
			return TokenFileConfig{
				Use:       true,
				Format:    filepath.Join(idCfg.tokenDir, "{{domain}}{{delimiter}}{{role}}.roletoken"),
				Delimiter: idCfg.roleTokenFilenameDelimiter,
			}
		}(),
	}
	return nil
}
