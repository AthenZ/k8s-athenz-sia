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
	"net"
	"strings"

	extutil "github.com/AthenZ/k8s-athenz-sia/v3/pkg/util"
)

type File struct {
	Cert   string
	Key    string
	CaCert string
}

type K8sSecretBackup struct {
	Use        bool
	SecretName string
	Mode       string // for log purpose only
}

type CopperArgosMode struct {
	Provider          string // provider service name
	AthenzDomainName  string
	AthenzServiceName string
	DnsSuffix         string // DNS suffix for the service certificate
	SaTokenFile       string // service account token that is used as identityd document for CopperArgos
	PodUID            string
	PodIP             net.IP
}

type ThirdPartyCertMode struct {
	// TODO:
}

type K8sSecretCertMode struct {
	// TODO:
}

type DerivedServiceCert struct {
	File            File
	K8sSecretBackup K8sSecretBackup
	CopperArgos     *CopperArgosMode    // disabled if nil
	LocalCert       *ThirdPartyCertMode // disabled if nil
	K8sSecretCert   *K8sSecretCertMode  // disabled if nil
}

// derivedServiceCertConfig ... // TODO
func (idCfg *IdentityConfig) derivedServiceCertConfig() error {
	idCfg.ServiceCert.File = File{
		Cert:   idCfg.certFile,
		Key:    idCfg.keyFile,
		CaCert: idCfg.caCertFile,
	}
	idCfg.ServiceCert.K8sSecretBackup = K8sSecretBackup{
		Use:        idCfg.certSecret != "" && strings.Contains(idCfg.backup, "read"),
		SecretName: idCfg.certSecret,
		Mode:       idCfg.backup,
	}

	if idCfg.providerService != "" {
		idCfg.ServiceCert.CopperArgos = &CopperArgosMode{
			Provider:          idCfg.providerService,
			AthenzDomainName:  extutil.NamespaceToDomain(idCfg.Namespace, idCfg.athenzPrefix, idCfg.athenzDomain, idCfg.athenzSuffix),
			AthenzServiceName: extutil.ServiceAccountToService(idCfg.ServiceAccount),
			DnsSuffix:         idCfg.dnsSuffix,
			SaTokenFile:       idCfg.saTokenFile,
			PodUID:            idCfg.podUID,
			PodIP:             idCfg.podIP,
		}
	} else if idCfg.keyFile != "" && idCfg.certFile != "" { // meaning third-party cert is provided, instead of using CopperArgos
		idCfg.ServiceCert.LocalCert = &ThirdPartyCertMode{}
	} else if idCfg.certSecret != "" && strings.Contains(idCfg.backup, "read") { // use kubernetes secret mode
		idCfg.ServiceCert.K8sSecretCert = &K8sSecretCertMode{}
	}
	// Empty ProviderService means the service cert feature is not enabled.

	return nil
}
