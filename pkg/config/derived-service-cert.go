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

package config

import (
	"crypto/x509/pkix"
	"fmt"
	"strings"

	extutil "github.com/AthenZ/k8s-athenz-sia/v3/pkg/util"
)

type CopperArgosMode struct {
	Use      bool
	Provider string // provider service name
	Sans     []string
	Subject  *pkix.Name // subject field for instance certificate

	AthenzDomainName  string
	AthenzServiceName string
}

type LocalCertMode struct {
	Use bool
}

type DerivedServiceCert struct {
	CopperArgos CopperArgosMode
	LocalCert   LocalCertMode // Use 3rd party provided service cert instead of CopperArgos
}

// derivedServiceCertConfig reads given configuration and sets the derived state of preparing service cert under the follow modes:
// - CopperArgos: Use CopperArgos Mode
// - LocalCert: Use 3rd party provided service cert instead of CopperArgos
// Also, there is a hidden mode where k8s-athenz-sia prepares service-cert with k8s-secret mode, but the state is managed in DerivedK8sSecretBackup instead,
// as the backup mode can be used for every mode, if enabled.
func (idCfg *IdentityConfig) derivedServiceCertConfig() error {
	// default:
	idCfg.ServiceCert = DerivedServiceCert{
		CopperArgos: CopperArgosMode{
			Use:               false,
			Provider:          "",
			AthenzDomainName:  "",
			AthenzServiceName: "",
		},
		LocalCert: LocalCertMode{Use: false},
	}

	if idCfg.providerService != "" {
		serviceName := extutil.ServiceAccountToService(idCfg.ServiceAccount)
		domainName := extutil.NamespaceToDomain(idCfg.Namespace, idCfg.athenzPrefix, idCfg.athenzDomain, idCfg.athenzSuffix)
		domainDNSPart := extutil.DomainToDNSPart(domainName)

		// set instance certificate specific attributes
		subject := &idCfg.certSubject.serviceCert
		subject.CommonName = fmt.Sprintf("%s.%s", domainName, serviceName)
		subject.OrganizationalUnit = []string{idCfg.providerService}

		idCfg.ServiceCert.CopperArgos = CopperArgosMode{
			Use:      true,
			Provider: idCfg.providerService,
			Sans: (func() []string {
				sans := []string{
					// The following are the default SANs for CopperArgos mode:
					fmt.Sprintf("%s.%s.%s", serviceName, domainDNSPart, idCfg.DNSSuffix),
					fmt.Sprintf("*.%s.%s.%s", serviceName, domainDNSPart, idCfg.DNSSuffix),
					fmt.Sprintf("%s.instanceid.athenz.%s", idCfg.PodUID, idCfg.DNSSuffix),
				}

				if len(idCfg.rawCertExtraSANDNSs) > 0 {
					sans = append(sans, strings.Split(idCfg.rawCertExtraSANDNSs, ",")...)
				}
				return sans
			})(),
			Subject:           subject,
			AthenzDomainName:  domainName,
			AthenzServiceName: serviceName,
		}
		return nil // Use CopperArgos Mode
	}

	// k8s-athenz-sia uses third-party service certificate, instead of using CopperArgos:
	if idCfg.KeyFile != "" && idCfg.CertFile != "" {
		idCfg.ServiceCert.LocalCert = LocalCertMode{Use: true}
		return nil // Use LocalCert Mode
	}

	return nil
}
