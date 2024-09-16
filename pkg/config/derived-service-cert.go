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
	extutil "github.com/AthenZ/k8s-athenz-sia/v3/pkg/util"
)

type CopperArgosMode struct {
	Use               bool
	Provider          string // provider service name
	AthenzDomainName  string
	AthenzServiceName string
}

type ThirdPartyCertMode struct {
	Use bool
}

type K8sSecretCertMode struct {
	Use bool
}

type DerivedServiceCert struct {
	CopperArgos   CopperArgosMode    // disabled if nil
	LocalCert     ThirdPartyCertMode // disabled if nil
	K8sSecretCert K8sSecretCertMode  // disabled if nil
}

// derivedServiceCertConfig ... // TODO
func (idCfg *IdentityConfig) derivedServiceCertConfig() error {
	// default:
	idCfg.ServiceCert = DerivedServiceCert{
		CopperArgos: CopperArgosMode{
			Use:               false,
			Provider:          "",
			AthenzDomainName:  "",
			AthenzServiceName: "",
		},
		LocalCert:     ThirdPartyCertMode{Use: false},
		K8sSecretCert: K8sSecretCertMode{Use: false},
	}

	if idCfg.providerService != "" {
		idCfg.ServiceCert.CopperArgos = CopperArgosMode{
			Use:               true,
			Provider:          idCfg.providerService,
			AthenzDomainName:  extutil.NamespaceToDomain(idCfg.Namespace, idCfg.AthenzPrefix, idCfg.AthenzDomain, idCfg.AthenzSuffix),
			AthenzServiceName: extutil.ServiceAccountToService(idCfg.ServiceAccount),
		}
	} else if idCfg.KeyFile != "" && idCfg.CertFile != "" { // meaning third-party cert is provided, instead of using CopperArgos
		idCfg.ServiceCert.LocalCert = ThirdPartyCertMode{Use: true}
	} else if idCfg.K8sSecretBackup.UseRead { // use kubernetes secret mode
		idCfg.ServiceCert.K8sSecretCert = K8sSecretCertMode{Use: true}
	}
	// Empty ProviderService means the service cert feature is not enabled.

	return nil
}
