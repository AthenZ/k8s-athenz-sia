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
	rdnSet = make([]pkix.RelativeDistinguishedNameSET, 0, len(ldapDn.RDNs))
	for _, rdn := range ldapDn.RDNs {
		ats := make([]pkix.AttributeTypeAndValue, len(rdn.Attributes))
		for j, at := range rdn.Attributes {
			asn1Oid, ok := ldapAttributeTypeOID[at.Type]
			if !ok {
				return nil, fmt.Errorf("Unknown attribute type when parsing distinguished names: %q", at.Type)
			}

			ats[j].Type = asn1Oid
			ats[j].Value = at.Value
		}
		// remove empty values
		ats = slices.Clip(slices.DeleteFunc(ats, func(at pkix.AttributeTypeAndValue) bool {
			return at.Value == ""
		}))
		// append only non-empty values
		if len(ats) != 0 {
			rdnSet = append(rdnSet, ats)
		}
	}

	// populates pkix.Name from pkix.RDNSequence
	name := &pkix.Name{}
	name.FillFromRDNSequence(&rdnSet)
	return name, nil
}
