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

type DerivedRoleCert struct {
	Use bool   // if fetching role certificate is enabled (de facto standard)
	Dir string // directory to store role certificates. Usually one, but can be multiple // TODO: make it string[]
	// TargetDomainRoles    []DomainRole // domain roles to fetch role certificates for
	// TargetDomainRolesStr string       // raw string of domain roles
	// Delimiter            string
}

type Derived struct {
	RoleCert DerivedRoleCert
	// accessToken DerivedAccessTokenConfig
	// roleToken    DerivedRoleTokenConfig
}

func (idCfg *IdentityConfig) loadDerivedState() error {
	if err := idCfg.derivedRoleCertState(); err != nil {
		return err
	}

	return nil
}

func (idCfg *IdentityConfig) derivedRoleCertState() error {
	// default:
	idCfg.D.RoleCert.Use = false

	// handle role certificates' derived state:
	targetDomainRoles, _ := parseTargetDomainRoles(idCfg.rawTargetDomainRoles)

	if len(targetDomainRoles) == 0 {
		return nil // disabled
	}

	if idCfg.roleCertDir == "" {
		return nil // disabled
	}

	// Enabled from no on:
	idCfg.D.RoleCert = DerivedRoleCert{
		Use: true,
		Dir: idCfg.roleCertDir,
	}
	return nil
}
