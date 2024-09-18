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
	Dir string
	// TODO: Add Format
	// Format    string
	Delimiter string
}

type DerivedTokenFile struct {
	AccessToken TokenFileConfig
	RoleToken   TokenFileConfig
}

// derivedTokenFileConfig reads given configuration and sets the derived state of outputting token file related configuration.
func (idCfg *IdentityConfig) derivedTokenFileConfig() error {
	// default:
	idCfg.TokenCache = DerivedTokenFile{
		AccessToken: TokenFileConfig{
			Use: false,
			Dir: "",
			// Format:    "",
			Delimiter: "",
		},
		RoleToken: TokenFileConfig{
			Use: false,
			Dir: "",
			// Format:    "",
			Delimiter: "",
		},
	}

	if idCfg.tokenDir == "" {
		return nil // disable
	}

	// Enable from now on:
	// access token:
	if strings.Contains(idCfg.TokenType, "accesstoken") {
		idCfg.TokenCache.AccessToken = TokenFileConfig{
			Use: true,
			Dir: idCfg.tokenDir,
			// Format:    filepath.Join(idCfg.TokenDir, "{{domain}}{{delimiter}}{{role}}.accesstoken"),
			Delimiter: ":role.",
		}
	}

	// role token:
	if strings.Contains(idCfg.TokenType, "roletoken") {
		idCfg.TokenCache.RoleToken = TokenFileConfig{
			Use: true,
			Dir: idCfg.tokenDir,
			// Format:    filepath.Join(idCfg.TokenDir, "{{domain}}{{delimiter}}{{role}}.roletoken"),
			Delimiter: ":role.",
		}
	}

	return nil
}
