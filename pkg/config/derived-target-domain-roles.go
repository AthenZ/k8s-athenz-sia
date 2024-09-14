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

	athenz "github.com/AthenZ/athenz/libs/go/sia/util"
	"github.com/AthenZ/k8s-athenz-sia/v3/third_party/log"
)

type DerivedTargetDomainRoles struct {
	RoleCerts []DomainRole
	// Tokens    []DomainRole
}

// derivedTargetDomainRoles first reads given target-domain-roles in raw type,
// and it parses into DomainRole type, and insert into derived state of fetching role certificates related configuration.
// each targetDomainRole is separated by commas.
// If the input string does not contain ":role",
// the entire string is considered as the domain and the role is set to an empty string.
// All successfully split pairs are stored in the domainRoles slice.
func (idCfg *IdentityConfig) derivedTargetDomainRoles() error {
	drs := strings.Split(idCfg.rawTargetDomainRoles, ",") // drs=domainRoles

	roleCertDomainRoles := make([]DomainRole, 0, len(drs))
	tokenDomainRoles := make([]DomainRole, 0, len(drs))

	for _, dr := range drs {
		targetDomain, targetRole, err := athenz.SplitRoleName(dr)

		// The entire specified string is considered as the domain name, and no role is specified:
		if err == nil {
			// TargetDomainRoles for RoleCert will only be applicable if both the domain and role are set:
			roleCertDomainRoles = append(roleCertDomainRoles, DomainRole{
				Domain: targetDomain,
				Role:   targetRole,
			})
		} else {
			targetDomain = dr
			targetRole = ""
			log.Debugf("TARGET_DOMAIN_ROLES[%s] does not contain ':role', so it will be treated as a domain name.", dr)
		}
		tokenDomainRoles = append(tokenDomainRoles, DomainRole{
			Domain: targetDomain,
			Role:   targetRole,
		})
	}

	idCfg.TokenTargetDomainRoles = tokenDomainRoles // TODO: Delete me and refactor by using the type DerivedTargetDomainRoles below:
	idCfg.TargetDomainRoles = DerivedTargetDomainRoles{
		RoleCerts: roleCertDomainRoles,
		// Tokens: tokenDomainRoles,
	}

	return nil
}
