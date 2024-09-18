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

type TokenFileConfig struct {
	Use bool
	// TODO: Add Format
	// Format    string
	Delimiter string
}

type DerivedTokenFile struct {
	Dir         string
	AccessToken TokenFileConfig
	RoleToken   TokenFileConfig
}

// derivedTokenFileConfig reads given configuration and sets the derived state of outputting token file related configuration.
func (idCfg *IdentityConfig) derivedTokenFileConfig() error {
	// default:
	idCfg.TokenFile = DerivedTokenFile{
		Dir: "",
		AccessToken: TokenFileConfig{
			Use: false,
			// Format:    "",
			Delimiter: "",
		},
		RoleToken: TokenFileConfig{
			Use: false,
			// Format:    "",
			Delimiter: "",
		},
	}

	// TODO: Apply the following instead?:
	// if idCfg.TokenDir == ""  || idCfg.TokenType == "" {
	if idCfg.tokenDir == "" {
		return nil // disabled
	}

	// Enable from now on:
	// access token:
	idCfg.TokenFile = DerivedTokenFile{
		Dir: idCfg.tokenDir,
		AccessToken: func() TokenFileConfig {
			// disabled
			if !strings.Contains(idCfg.TokenType, "accesstoken") {
				return TokenFileConfig{
					Use: false,
					// Format:    "",
					Delimiter: "",
				}
			}
			return TokenFileConfig{
				Use: true,
				// Format:    filepath.Join(idCfg.TokenDir, "{{domain}}{{delimiter}}{{role}}.accesstoken"),
				Delimiter: ":role.",
			}

		}(),
		RoleToken: func() TokenFileConfig {
			// disabled
			if !strings.Contains(idCfg.TokenType, "roletoken") {
				return TokenFileConfig{
					Use: false,
					// Format:    "",
					Delimiter: "",
				}
			}
			return TokenFileConfig{
				Use: true,
				// Format:    filepath.Join(idCfg.TokenDir, "{{domain}}{{delimiter}}{{role}}.roletoken"),
				Delimiter: ":role.",
			}
		}(),
	}
	return nil
}
