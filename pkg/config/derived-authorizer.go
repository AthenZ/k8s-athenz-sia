// Copyright 2024 LY Corporation
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

package config

import "time"

// DerivedAuthorizer contains the derived configuration for the authorizer service
type DerivedAuthorizer struct {
	Use                                   bool          // whether to use the authorizer server
	Addr                                  string        // authorizer server address
	Endpoint                              string        // authorizer server endpoint
	PolicyDomains                         string        // Athenz policy domains (comma-separated)
	CacheInterval                         time.Duration // authorization cache expiration interval
	PolicyRefreshInterval                 time.Duration // policy refresh interval
	PublicKeyRefreshInterval              time.Duration // public key refresh interval
	EnableMTLSCertificateBoundAccessToken bool          // enable mTLS certificate bound access token
	RoleAuthHeader                        string        // role authentication header name
}

func (idCfg *IdentityConfig) derivedAuthorizerConfig() error {
	idCfg.Authorizer = DerivedAuthorizer{
		Use:                                   false,
		Addr:                                  "",
		Endpoint:                              "/authorize",
		PolicyDomains:                         "",
		CacheInterval:                         5 * time.Minute,
		PolicyRefreshInterval:                 1 * time.Hour,
		PublicKeyRefreshInterval:              24 * time.Hour,
		EnableMTLSCertificateBoundAccessToken: false,
		RoleAuthHeader:                        DEFAULT_ROLE_AUTH_HEADER,
	}

	if idCfg.Init {
		return nil // disabled
	}
	if idCfg.AuthorizationServerAddr == "" || idCfg.AuthorizationPolicyDomains == "" {
		return nil // disabled
	}

	idCfg.Authorizer = DerivedAuthorizer{
		Use:                                   true,
		Addr:                                  idCfg.AuthorizationServerAddr,
		PolicyDomains:                         idCfg.AuthorizationPolicyDomains,
		CacheInterval:                         idCfg.AuthorizationCacheInterval,
		PolicyRefreshInterval:                 idCfg.PolicyRefreshInterval,
		PublicKeyRefreshInterval:              idCfg.PublicKeyRefreshInterval,
		EnableMTLSCertificateBoundAccessToken: idCfg.EnableMTLSCertificateBoundAccessToken,
		RoleAuthHeader:                        idCfg.TokenServer.HeaderToken.RoleAuthHeader,
	}

	return nil
}
