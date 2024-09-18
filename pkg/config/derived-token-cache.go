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

type WriteFileConfig struct {
	Use bool
	Dir string
	// TODO: Add Format
	// Format    string
	Delimiter string
}

type DerivedTokenCache struct {
	TargetDomainRoles []DomainRole  // domain roles to fetch tokens
	Refresh           time.Duration // refresh interval
	ExpirySeconds     int
	AccessToken       WriteFileConfig
	RoleToken         WriteFileConfig
}

// // derivedAccessToken ... TODO: Comment
func (idCfg *IdentityConfig) derivedTokenChacheConfig() error {
	// default:
	idCfg.TokenCache = DerivedTokenCache{
		TargetDomainRoles: idCfg.targetDomainRoles.tokens,
		Refresh:           idCfg.tokenRefresh,
		ExpirySeconds:     int(idCfg.tokenExpiry.Seconds()),
		AccessToken: WriteFileConfig{
			Use: false,
			Dir: "",
			// Format:    "",
			Delimiter: "",
		},
		RoleToken: WriteFileConfig{
			Use: false,
			Dir: "",
			// Format:    "",
			Delimiter: "",
		},
	}

	// access token:
	if strings.Contains(idCfg.TokenType, "accesstoken") {
		idCfg.TokenCache.AccessToken = WriteFileConfig{
			Use: true,
			Dir: idCfg.tokenDir,
			// Format:    filepath.Join(idCfg.TokenDir, "{{domain}}{{delimiter}}{{role}}.accesstoken"),
			Delimiter: ":role.",
		}
	}

	// role token:
	if strings.Contains(idCfg.TokenType, "roletoken") {
		idCfg.TokenCache.RoleToken = WriteFileConfig{
			Use: true,
			Dir: idCfg.tokenDir,
			// Format:    filepath.Join(idCfg.TokenDir, "{{domain}}{{delimiter}}{{role}}.roletoken"),
			Delimiter: ":role.",
		}
	}

	return nil
}
