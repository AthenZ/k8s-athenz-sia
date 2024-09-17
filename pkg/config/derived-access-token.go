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

import "strings"

type DerivedAccessToken struct {
	Use               bool         // if fetching access token as files is enabled (de facto standard)
	Dir               string       // directory to store access token. Usually one, but can be multiple
	TargetDomainRoles []DomainRole // domain roles to fetch access tokens
	Delimiter         string
}

// // derivedAccessToken ... TODO: Comment
func (idCfg *IdentityConfig) derivedAccessTokenConfig() error {
	idCfg.AccessToken.Use = false

	if len(idCfg.targetDomainRoles.tokens) == 0 || idCfg.tokenDir == "" || strings.Contains(idCfg.TokenType, "accesstoken") {
		return nil // disabled
	}

	// Enabled from now on:
	idCfg.AccessToken = DerivedAccessToken{
		Use:               true,
		Dir:               idCfg.tokenDir,
		TargetDomainRoles: idCfg.targetDomainRoles.tokens,
		Delimiter:         ":role.",
	}
	return nil
}
