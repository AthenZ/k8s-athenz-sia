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
	roleCerts []DomainRole // private as the derived state is used only within the config package
	// tokens    []DomainRole // private as the derived state is used only within the config package
}

// derivedTargetDomainRoles sets the DerivedTargetDomainRoles with the given rawTargetDomainRoles.
// rawTargetDomainRoles is a comma-separated string of targetDomainRoles.
// Each targetDomainRole may or may not contain the delimiter ":role".
// If a targetDomainRole does not contain ":role", the entire string is considered as the Athenz Domain, and the Athenz Role is set to an empty string.
// If a targetDomainRole contains ":role", the string is split into two parts: the Athenz Domain and the Athenz Role.
func (idCfg *IdentityConfig) derivedTargetDomainRoles() error {
	// TODO: Maybe use trim() here, so that empty strings are not considered as valid targetDomainRoles:
	if idCfg.rawTargetDomainRoles == "" {
		return nil
	}

	elements := strings.Split(idCfg.rawTargetDomainRoles, ",") // TODO: Rename me to targetDomainRoles (OR, drs)
	roleCertDomainRoles := make([]DomainRole, 0, len(elements))
	tokenDomainRoles := make([]DomainRole, 0, len(elements))

	for _, domainRole := range elements {
		targetDomain, targetRole, err := athenz.SplitRoleName(domainRole)

		if err == nil {
			// TargetDomainRoles for RoleCert will only be applicable if both the domain and role are set:
			roleCertDomainRoles = append(roleCertDomainRoles, DomainRole{
				Domain: targetDomain,
				Role:   targetRole,
			})
		} else {
			// The entire specified string is considered as the domain name, and no role is specified:
			targetDomain = domainRole
			targetRole = ""
			log.Debugf("TARGET_DOMAIN_ROLES[%s] does not contain ':role', so it will be treated as a domain name.", domainRole)
		}
		tokenDomainRoles = append(tokenDomainRoles, DomainRole{
			Domain: targetDomain,
			Role:   targetRole,
		})
	}

	idCfg.TokenTargetDomainRoles = tokenDomainRoles // TODO: Delete me and refactor by using the type DerivedTargetDomainRoles below:
	idCfg.targetDomainRoles = DerivedTargetDomainRoles{
		roleCerts: roleCertDomainRoles,
		// tokens:    tokenDomainRoles,
	}

	return nil
}
