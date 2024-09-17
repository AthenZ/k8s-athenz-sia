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

type DerivedTokenServer struct {
	Use           bool
	UseAT         bool // if fetching access token as files is enabled
	UseRT         bool // if fetching role token as files is enabled
	ExpirySeconds int  // ExpirySeconds is the number of seconds before the token expires
}

// TODO: Use idCfg.targetDomainRoles.TokenTargetDomainRoles

// derivedTokenServerConfig ... // TODO: Comment
func (idCfg *IdentityConfig) derivedTokenServerConfig() error {
	// TODO: Write
	// default (disabled):
	idCfg.WriteToken = DerivedToken{
		Use:               false,
		UseAT:             false,
		UseRT:             false,
		Dir:               "",
		TargetDomainRoles: []DomainRole{},
	}

	// TODO: Apply the following instead?:
	// if idCfg.TokenDir == ""  || idCfg.TokenType == "" {
	if idCfg.tokenDir == "" {
		return nil
	}

	// Enable from now on:
	idCfg.WriteToken = DerivedToken{
		Use:               true,
		UseAT:             strings.Contains(idCfg.TokenType, "accesstoken"),
		UseRT:             strings.Contains(idCfg.TokenType, "roletoken"),
		Dir:               idCfg.tokenDir,
		TargetDomainRoles: []DomainRole{},
		ExpirySeconds:     int(idCfg.tokenExpiry.Seconds()),
	}

	return nil
}
