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
	"encoding/asn1"
	"fmt"

	"slices"

	"github.com/go-ldap/ldap/v3"
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
			return fmt.Errorf("Non-empty SERIALNUMBER attribute: invalid CERT_SUBJECT[%q]", idCfg.rawCertSubject)
		}
		if dn.CommonName != "" {
			// role cert common name should follow Athenz specification
			return fmt.Errorf("Non-empty CN attribute: invalid CERT_SUBJECT[%q]", idCfg.rawCertSubject)
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
		Country:            slices.Clip(slices.Clone(subject.Country)), // copy the slice and remove unused capacity (ref: https://pkg.go.dev/slices#Clone)
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

// copied from: https://github.com/golang/go/blob/go1.23.6/src/crypto/x509/pkix/pkix.go#L184-L194
var (
	oidCountry            = []int{2, 5, 4, 6}
	oidOrganization       = []int{2, 5, 4, 10}
	oidOrganizationalUnit = []int{2, 5, 4, 11}
	oidCommonName         = []int{2, 5, 4, 3}
	oidSerialNumber       = []int{2, 5, 4, 5}
	oidLocality           = []int{2, 5, 4, 7}
	oidProvince           = []int{2, 5, 4, 8}
	oidStreetAddress      = []int{2, 5, 4, 9}
	oidPostalCode         = []int{2, 5, 4, 17}
)

// reversed from https://github.com/golang/go/blob/go1.23.6/src/crypto/x509/pkix/pkix.go#L26-L36
// according to https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.9: Implementations of this specification MUST be prepared to receive the following standard attribute types in issuer and subject
// object identifiers are defined in https://datatracker.ietf.org/doc/html/rfc4519#section-2.3
var ldapAttributeTypeOID = map[string]asn1.ObjectIdentifier{
	"C":            oidCountry,
	"O":            oidOrganization,
	"OU":           oidOrganizationalUnit,
	"CN":           oidCommonName,
	"SERIALNUMBER": oidSerialNumber,
	"L":            oidLocality,
	"ST":           oidProvince,
	"STREET":       oidStreetAddress,
	"POSTALCODE":   oidPostalCode,
}

// parseDN parses Distinguished Names from string with format defined in https://datatracker.ietf.org/doc/html/rfc4514#section-4
func parseDN(dn string) (*pkix.Name, error) {
	// parse string to ldap.DN
	ldapDn, err := ldap.ParseDN(dn)
	if err != nil {
		return nil, err
	}

	// convert ldap.RelativeDN to pkix.RDNSequence
	var rdnSet pkix.RDNSequence
	rdnSet = make([]pkix.RelativeDistinguishedNameSET, len(ldapDn.RDNs))
	for i, rdn := range ldapDn.RDNs {
		ats := make([]pkix.AttributeTypeAndValue, len(rdn.Attributes))
		for j, at := range rdn.Attributes {
			asn1Oid, ok := ldapAttributeTypeOID[at.Type]
			if !ok {
				return nil, fmt.Errorf("Unknown attribute type when parsing distinguished names: %q", at.Type)
			}

			ats[j].Type = asn1Oid
			ats[j].Value = at.Value
		}
		rdnSet[i] = ats
	}

	// populates pkix.Name from pkix.RDNSequence
	name := &pkix.Name{}
	name.FillFromRDNSequence(&rdnSet)
	return name, nil
}

// applyDefaultAttributes applies default attributes to the input name if the attribute is empty
func applyDefaultAttributes(name, defaultName pkix.Name) pkix.Name {
	valuedOrDefault := func(s, d []string) []string {
		if len(s) == 0 {
			return d
		}
		return s
	}

	name.Country = valuedOrDefault(name.Country, defaultName.Country)
	name.Organization = valuedOrDefault(name.Organization, defaultName.Organization)
	name.OrganizationalUnit = valuedOrDefault(name.OrganizationalUnit, defaultName.OrganizationalUnit)
	name.Locality = valuedOrDefault(name.Locality, defaultName.Locality)
	name.Province = valuedOrDefault(name.Province, defaultName.Province)
	name.StreetAddress = valuedOrDefault(name.StreetAddress, defaultName.StreetAddress)
	name.PostalCode = valuedOrDefault(name.PostalCode, defaultName.PostalCode)
	return name
}

// trimEmptyAttributeValue trims empty string attributes
func trimEmptyAttributeValue(name pkix.Name) pkix.Name {
	trimEmpty := func(ss []string) []string {
		ss = slices.DeleteFunc(ss, func(s string) bool {
			return s == ""
		})
		if len(ss) == 0 {
			return nil
		}
		return slices.Clip(ss)
	}

	name.Country = trimEmpty(name.Country)
	name.Organization = trimEmpty(name.Organization)
	name.OrganizationalUnit = trimEmpty(name.OrganizationalUnit)
	name.Locality = trimEmpty(name.Locality)
	name.Province = trimEmpty(name.Province)
	name.StreetAddress = trimEmpty(name.StreetAddress)
	name.PostalCode = trimEmpty(name.PostalCode)
	return name
}
