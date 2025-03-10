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

	"slices"
)

type DerivedCertSubject struct {
	roleCert    pkix.Name // private as the derived state is used only within the config package
	serviceCert pkix.Name // private as the derived state is used only within the config package
}

// derivedCertSubject sets the DerivedCertSubject with the given rawCertSubject.
// 1. Parses the string in RFC 4514 format to pkix.Name struct.
// 2. Returns error if CN, SERIALNUMBER and other unknown attributes are set.
// 3. Apply default value if the corresponding attribute is not set.
func (idCfg *IdentityConfig) derivedCertSubject() error {
	// parse certificate subject
	subject := pkix.Name{}
	if idCfg.rawCertSubject != "" {
		dn, err := parseDN(idCfg.rawCertSubject)
		if err != nil {
			return fmt.Errorf("Failed to parse CERT_SUBJECT[%q]: %w", idCfg.rawCertSubject, err)
		}
		if dn.SerialNumber != "" {
			// serial number should be managed by Athenz ZTS
			return fmt.Errorf("Non-empty SERIALNUMBER attribute: invalid CERT_SUBJECT[%q]: %w", idCfg.rawCertSubject, err)
		}
		if dn.CommonName != "" {
			// role cert common name should follow Athenz specification
			return fmt.Errorf("Non-empty CN attribute: invalid CERT_SUBJECT[%q]: %w", idCfg.rawCertSubject, err)
		}
		subject = *dn
	}

	// default values to the corresponding attributes
	// TODO: deprecate: ATHENZ_SIA_DEFAULT_COUNTRY, ATHENZ_SIA_DEFAULT_PROVINCE, ATHENZ_SIA_DEFAULT_ORGANIZATION, ATHENZ_SIA_DEFAULT_ORGANIZATIONAL_UNIT
	// TODO: use DEFAULT_SUBJECT as default values
	subject = trimEmptyAttributeValue(applyDefaultAttributes(subject, pkix.Name{
		Country:            []string{DEFAULT_COUNTRY},
		Province:           []string{DEFAULT_PROVINCE},
		Organization:       []string{DEFAULT_ORGANIZATION},
		OrganizationalUnit: []string{DEFAULT_ORGANIZATIONAL_UNIT},
	}))

	// clone certificate subject
	idCfg.certSubject.roleCert = subject
	idCfg.certSubject.serviceCert = pkix.Name{
		Country:            slices.Clip(slices.Clone(subject.Country)),
		Organization:       slices.Clip(slices.Clone(subject.Organization)),
		OrganizationalUnit: slices.Clip(slices.Clone(subject.OrganizationalUnit)),
		Locality:           slices.Clip(slices.Clone(subject.Locality)),
		Province:           slices.Clip(slices.Clone(subject.Province)),
		StreetAddress:      slices.Clip(slices.Clone(subject.StreetAddress)),
		PostalCode:         slices.Clip(slices.Clone(subject.PostalCode)),
		SerialNumber:       subject.SerialNumber,
		CommonName:         subject.CommonName,
		Names:              slices.Clip(slices.Clone(subject.Names)),
		ExtraNames:         slices.Clip(slices.Clone(subject.ExtraNames)),
	}
	return nil
}
