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

type CopperArgosMode struct {
	Provider string // provider service name
	// certPath         string
	// keyPath          string
}

type ThirdPartyCertMode struct {
	// certPath         string
	// keyPath          string
}

type K8sSecretCertMode struct {
	// TODO:
}

type DerivedServiceCert struct {
	CopperArgos   *CopperArgosMode    // disabled if nil
	LocalCert     *ThirdPartyCertMode // disabled if nil
	K8sSecretCert *K8sSecretCertMode  // disabled if nil
}

// derivedServiceCertConfig ... // TODO
func (idCfg *IdentityConfig) derivedServiceCertConfig() error {

	if idCfg.providerService != "" {
		idCfg.ServiceCert.CopperArgos = &CopperArgosMode{
			Provider: idCfg.providerService,
		}
	} else if idCfg.KeyFile != "" && idCfg.CertFile != "" { // meaning third-party cert is provided, instead of using CopperArgos
		idCfg.ServiceCert.LocalCert = &ThirdPartyCertMode{}
	} else if idCfg.CertSecret != "" && strings.Contains(idCfg.Backup, "read") { // use kubernetes secret mode
		idCfg.ServiceCert.K8sSecretCert = &K8sSecretCertMode{}
	}
	// Empty ProviderService means the service cert feature is not enabled.

	return nil
}
