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
	"errors"
	"reflect"
	"testing"
)

func TestIdentityConfig_derivedCertSubject(t *testing.T) {
	resetDefaults := func() {
		DEFAULT_COUNTRY = ""
		DEFAULT_PROVINCE = ""
		DEFAULT_ORGANIZATION = ""
		DEFAULT_ORGANIZATIONAL_UNIT = "Athenz"
	}

	type fields struct {
		rawCertSubject string
	}
	tests := []struct {
		name    string
		fields  fields
		want    pkix.Name
		wantErr error
		before  func()
		after   func()
	}{
		{
			name: "Valid role cert subject",
			fields: fields{
				rawCertSubject: "OU=dummyOrganizationalUnit,O=dummyOrganization,L=dummyLocality,ST=dummyProvince,C=dummyCountry,POSTALCODE=dummyPostalCode,STREET=dummyStreetAddress",
			},
			want: pkix.Name{
				OrganizationalUnit: []string{"dummyOrganizationalUnit"},
				Organization:       []string{"dummyOrganization"},
				Locality:           []string{"dummyLocality"},
				Province:           []string{"dummyProvince"},
				Country:            []string{"dummyCountry"},
				PostalCode:         []string{"dummyPostalCode"},
				StreetAddress:      []string{"dummyStreetAddress"},
			},
			wantErr: nil,
		},
		{
			name: "Empty rawCertSubject",
			before: func() {
				DEFAULT_COUNTRY = ""
				DEFAULT_PROVINCE = ""
				DEFAULT_ORGANIZATION = ""
				DEFAULT_ORGANIZATIONAL_UNIT = "Athenz"
			},
			after: resetDefaults,
			fields: fields{
				rawCertSubject: "",
			},
			want: pkix.Name{
				OrganizationalUnit: []string{"Athenz"},
			},
			wantErr: nil,
		},
		{
			name: "Multi-value attribute rawCertSubject",
			fields: fields{
				rawCertSubject: "OU=,OU=1,OU=2",
			},
			want: pkix.Name{
				OrganizationalUnit: []string{"1", "2"},
			},
			wantErr: nil,
		},
		{
			name: "Use default attribute value if not set",
			before: func() {
				DEFAULT_COUNTRY = "C"
				DEFAULT_PROVINCE = "CA"
				DEFAULT_ORGANIZATION = "Organization"
				DEFAULT_ORGANIZATIONAL_UNIT = "OrganizationalUnit"
			},
			after: resetDefaults,
			fields: fields{
				rawCertSubject: "L=Locality",
			},
			want: pkix.Name{
				Country:            []string{"C"},
				Province:           []string{"CA"},
				Organization:       []string{"Organization"},
				OrganizationalUnit: []string{"OrganizationalUnit"},
				Locality:           []string{"Locality"},
			},
			wantErr: nil,
		},
		{
			name: "Use default attribute value if attribute value is empty",
			before: func() {
				DEFAULT_COUNTRY = ""
				DEFAULT_PROVINCE = ""
				DEFAULT_ORGANIZATION = ""
				DEFAULT_ORGANIZATIONAL_UNIT = "Athenz"
			},
			after: resetDefaults,
			fields: fields{
				rawCertSubject: "O=dummyOrganization,OU=",
			},
			want: pkix.Name{
				OrganizationalUnit: nil,
				Organization:       []string{"dummyOrganization"},
			},
			wantErr: nil,
		},
		{
			name: "Override default attribute value if set explicitly",
			fields: fields{
				rawCertSubject: "O=dummyOrganization,OU=dummyOrganizationalUnit",
			},
			want: pkix.Name{
				OrganizationalUnit: []string{"dummyOrganizationalUnit"},
				Organization:       []string{"dummyOrganization"},
			},
			wantErr: nil,
		},
		{
			name: "Invalid rawCertSubject",
			fields: fields{
				rawCertSubject: "INVALID_DN",
			},
			want:    pkix.Name{},
			wantErr: errors.New(`Failed to parse CERT_SUBJECT["INVALID_DN"]: DN ended with incomplete type, value pair`),
		},
		{
			name: "Unknown attribute in rawCertSubject",
			fields: fields{
				rawCertSubject: "INVALID_DN=DN",
			},
			want:    pkix.Name{},
			wantErr: errors.New(`Failed to parse CERT_SUBJECT["INVALID_DN=DN"]: Unknown attribute type when parsing distinguished names: "INVALID_DN"`),
		},
		{
			name: "Non-empty SERIALNUMBER in rawCertSubject",
			fields: fields{
				rawCertSubject: "SERIALNUMBER=dummySerialNumber",
			},
			want:    pkix.Name{},
			wantErr: errors.New(`Non-empty SERIALNUMBER attribute: invalid CERT_SUBJECT["SERIALNUMBER=dummySerialNumber"]`),
		},
		{
			name: "Non-empty CN in rawCertSubject",
			fields: fields{
				rawCertSubject: "CN=dummyCommonName",
			},
			want:    pkix.Name{},
			wantErr: errors.New(`Non-empty CN attribute: invalid CERT_SUBJECT["CN=dummyCommonName"]`),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idCfg := IdentityConfig{
				rawCertSubject: tt.fields.rawCertSubject,
			}

			// run test method
			if tt.before != nil {
				tt.before()
			}
			err := idCfg.derivedCertSubject()
			if tt.after != nil {
				tt.after()
			}

			// assert equal

			if tt.wantErr == nil || err == nil {
				if tt.wantErr != err {
					t.Errorf("IdentityConfig.derivedCertSubject() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
			} else {
				if tt.wantErr.Error() != err.Error() {
					t.Errorf("IdentityConfig.derivedCertSubject() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
			}
			roleCert := idCfg.certSubject.roleCert
			serviceCert := idCfg.certSubject.serviceCert
			if roleCert.String() != tt.want.String() {
				t.Errorf("IdentityConfig.derivedCertSubject() roleCert = %+v, want %+v", idCfg.certSubject.roleCert, tt.want)
			}
			if serviceCert.String() != tt.want.String() {
				t.Errorf("IdentityConfig.derivedCertSubject() serviceCert = %+v, want %+v", idCfg.certSubject.serviceCert, tt.want)
			}
		})
	}
}

func TestIdentityConfig_derivedCertSubject_cloned(t *testing.T) {
	type fields struct {
		rawCertSubject string
	}
	tests := []struct {
		name    string
		fields  fields
		want    DerivedCertSubject
		wantErr bool
		after   func(*DerivedCertSubject)
	}{
		{
			name: "roleCert is independent from serviceCert",
			fields: fields{
				rawCertSubject: "OU=dummyOrganizationalUnit,O=dummyOrganization,L=dummyLocality,ST=dummyProvince,C=dummyCountry,POSTALCODE=dummyPostalCode,STREET=dummyStreetAddress",
			},
			after: func(got *DerivedCertSubject) {
				got.roleCert.OrganizationalUnit[0] = "independent"
				got.roleCert.Organization[0] = "independent"
				got.roleCert.Locality[0] = "independent"
				got.roleCert.Province[0] = "independent"
				got.roleCert.Country[0] = "independent"
				got.roleCert.PostalCode[0] = "independent"
				got.roleCert.StreetAddress[0] = "independent"
			},
			want: DerivedCertSubject{
				roleCert: pkix.Name{
					OrganizationalUnit: []string{"independent"},
					Organization:       []string{"independent"},
					Locality:           []string{"independent"},
					Province:           []string{"independent"},
					Country:            []string{"independent"},
					PostalCode:         []string{"independent"},
					StreetAddress:      []string{"independent"},
				},
				serviceCert: pkix.Name{
					OrganizationalUnit: []string{"dummyOrganizationalUnit"},
					Organization:       []string{"dummyOrganization"},
					Locality:           []string{"dummyLocality"},
					Province:           []string{"dummyProvince"},
					Country:            []string{"dummyCountry"},
					PostalCode:         []string{"dummyPostalCode"},
					StreetAddress:      []string{"dummyStreetAddress"},
				},
			},
			wantErr: false,
		},
		{
			name: "serviceCert is independent from roleCert",
			fields: fields{
				rawCertSubject: "OU=dummyOrganizationalUnit,O=dummyOrganization,L=dummyLocality,ST=dummyProvince,C=dummyCountry,POSTALCODE=dummyPostalCode,STREET=dummyStreetAddress",
			},
			after: func(got *DerivedCertSubject) {
				got.serviceCert.OrganizationalUnit[0] = "independent"
				got.serviceCert.Organization[0] = "independent"
				got.serviceCert.Locality[0] = "independent"
				got.serviceCert.Province[0] = "independent"
				got.serviceCert.Country[0] = "independent"
				got.serviceCert.PostalCode[0] = "independent"
				got.serviceCert.StreetAddress[0] = "independent"
			},
			want: DerivedCertSubject{
				roleCert: pkix.Name{
					OrganizationalUnit: []string{"dummyOrganizationalUnit"},
					Organization:       []string{"dummyOrganization"},
					Locality:           []string{"dummyLocality"},
					Province:           []string{"dummyProvince"},
					Country:            []string{"dummyCountry"},
					PostalCode:         []string{"dummyPostalCode"},
					StreetAddress:      []string{"dummyStreetAddress"},
				},
				serviceCert: pkix.Name{
					OrganizationalUnit: []string{"independent"},
					Organization:       []string{"independent"},
					Locality:           []string{"independent"},
					Province:           []string{"independent"},
					Country:            []string{"independent"},
					PostalCode:         []string{"independent"},
					StreetAddress:      []string{"independent"},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idCfg := IdentityConfig{
				rawCertSubject: tt.fields.rawCertSubject,
			}

			// run test method
			if err := idCfg.derivedCertSubject(); (err != nil) != tt.wantErr {
				t.Errorf("IdentityConfig.derivedCertSubject() error = %v, wantErr %v", err, tt.wantErr)
			}
			got := idCfg.certSubject
			if tt.after != nil {
				tt.after(&got)
			}

			// assert equal
			if got.roleCert.String() != tt.want.roleCert.String() {
				t.Errorf("IdentityConfig.derivedCertSubject() cloned roleCert = %+v, want %+v", got.roleCert, tt.want.roleCert)
			}
			if got.serviceCert.String() != tt.want.serviceCert.String() {
				t.Errorf("IdentityConfig.derivedCertSubject() cloned serviceCert = %+v, want %+v", got.serviceCert, tt.want.serviceCert)
			}
		})
	}
}

func Test_parseDN(t *testing.T) {
	type args struct {
		dn string
	}
	tests := []struct {
		name    string
		args    args
		want    *pkix.Name
		wantErr bool
	}{
		{
			name: "Valid DN",
			args: args{
				dn: "CN=dummyCommonName,OU=dummyOrganizationalUnit,O=dummyOrganization,L=dummyLocality,ST=dummyProvince,C=dummyCountry,POSTALCODE=dummyPostalCode,STREET=dummyStreetAddress,SERIALNUMBER=dummySerialNumber",
			},
			want: &pkix.Name{
				CommonName:         "dummyCommonName",
				SerialNumber:       "dummySerialNumber",
				OrganizationalUnit: []string{"dummyOrganizationalUnit"},
				Organization:       []string{"dummyOrganization"},
				Locality:           []string{"dummyLocality"},
				Province:           []string{"dummyProvince"},
				Country:            []string{"dummyCountry"},
				PostalCode:         []string{"dummyPostalCode"},
				StreetAddress:      []string{"dummyStreetAddress"},
			},
			wantErr: false,
		},
		{
			name: "Empty string",
			args: args{
				dn: "",
			},
			want:    &pkix.Name{},
			wantErr: false,
		},
		{
			name: "Empty attribute value",
			args: args{
				dn: "CN=,OU=,O=,L=,ST=,C=,POSTALCODE=,STREET=,SERIALNUMBER=",
			},
			want: &pkix.Name{
				OrganizationalUnit: []string{""},
				Organization:       []string{""},
				Locality:           []string{""},
				Province:           []string{""},
				Country:            []string{""},
				PostalCode:         []string{""},
				StreetAddress:      []string{""},
			},
			wantErr: false,
		},
		{
			name: "Invalid DN",
			args: args{
				dn: "INVALID_DN",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "Partially invalid DN",
			args: args{
				dn: "CN=dummyCommonName,INVALID_DN",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "Unknown DN attribute type",
			args: args{
				dn: "CN=dummyCommonName,UNKNOWN=dummyUnknown",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "Repeated attribute OU",
			args: args{
				dn: "CN=jsmith,OU=example,OU=net",
			},
			want: &pkix.Name{
				CommonName:         "jsmith",
				OrganizationalUnit: []string{"example", "net"},
			},
			wantErr: false,
		},
		{
			name: "Repeated attribute OU with empty values",
			args: args{
				dn: "CN=jsmith,OU=,OU=example,OU=net,OU=",
			},
			want: &pkix.Name{
				CommonName:         "jsmith",
				OrganizationalUnit: []string{"", "example", "net", ""},
			},
			wantErr: false,
		},
		{
			name: "Multi-valued RDN",
			args: args{
				dn: "OU=Sales+CN=J.  Smith,OU=example,OU=net",
			},
			want: &pkix.Name{
				CommonName:         "J.  Smith",
				OrganizationalUnit: []string{"Sales", "example", "net"},
			},
			wantErr: false,
		},
		{
			name: "Escaping of special characters",
			args: args{
				dn: `CN=James \"Jim\" Smith\, III,OU=example,OU=net`,
			},
			want: &pkix.Name{
				CommonName:         `James "Jim" Smith, III`,
				OrganizationalUnit: []string{"example", "net"},
			},
			wantErr: false,
		},
		{
			name: "Value that contains a carriage return character",
			args: args{
				dn: `CN=Before\0dAfter,OU=example,OU=net`,
			},
			want: &pkix.Name{
				CommonName:         "Before\rAfter",
				OrganizationalUnit: []string{"example", "net"},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseDN(tt.args.dn)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseDN() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.want == nil {
				if got != nil {
					t.Errorf("parseDN() = %v, want %v", got, tt.want)
				}
				return
			}
			if got.String() != tt.want.String() {
				t.Errorf("parseDN() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestApplyDefaultAttributes(t *testing.T) {
	type args struct {
		name        pkix.Name
		defaultName pkix.Name
	}
	tests := []struct {
		name string
		args args
		want pkix.Name
	}{
		{
			name: "Apply default attributes",
			args: args{
				name: pkix.Name{},
				defaultName: pkix.Name{
					CommonName:         "defaultCommonName",
					SerialNumber:       "defaultSerialNumber",
					OrganizationalUnit: []string{"defaultOrganizationalUnit"},
					Organization:       []string{"defaultOrganization"},
					Locality:           []string{"defaultLocality"},
					Province:           []string{"defaultProvince"},
					Country:            []string{"defaultCountry"},
					PostalCode:         []string{"defaultPostalCode"},
					StreetAddress:      []string{"defaultStreetAddress"},
				},
			},
			want: pkix.Name{
				OrganizationalUnit: []string{"defaultOrganizationalUnit"},
				Organization:       []string{"defaultOrganization"},
				Locality:           []string{"defaultLocality"},
				Province:           []string{"defaultProvince"},
				Country:            []string{"defaultCountry"},
				PostalCode:         []string{"defaultPostalCode"},
				StreetAddress:      []string{"defaultStreetAddress"},
			},
		},
		{
			name: "Apply default attributes with empty attributes",
			args: args{
				name: pkix.Name{},
				defaultName: pkix.Name{
					CommonName:         "defaultCommonName",
					SerialNumber:       "defaultSerialNumber",
					OrganizationalUnit: []string{"defaultOrganizationalUnit"},
					Organization:       []string{"defaultOrganization"},
					Locality:           []string{"", ""},
					Province:           []string{""},
					Country:            []string{""},
					// PostalCode:         []string{"defaultPostalCode"},
					// StreetAddress:      []string{"defaultStreetAddress"}},
				},
			},
			want: pkix.Name{
				OrganizationalUnit: []string{"defaultOrganizationalUnit"},
				Organization:       []string{"defaultOrganization"},
				Locality:           []string{"", ""},
				Province:           []string{""},
				Country:            []string{""},
				PostalCode:         nil,
				StreetAddress:      nil,
			},
		},
		{
			name: "Keep non-empty attributes",
			args: args{
				name: pkix.Name{
					CommonName:         "dummyCommonName",
					SerialNumber:       "dummySerialNumber",
					OrganizationalUnit: []string{"dummyOrganizationalUnit"},
					Organization:       []string{"dummyOrganization"},
					Locality:           []string{"dummyLocality"},
					Province:           []string{"dummyProvince"},
					Country:            []string{"dummyCountry"},
					PostalCode:         []string{"dummyPostalCode"},
					StreetAddress:      []string{"dummyStreetAddress"},
				},
				defaultName: pkix.Name{
					CommonName:         "defaultCommonName",
					SerialNumber:       "defaultSerialNumber",
					OrganizationalUnit: []string{"defaultOrganizationalUnit"},
					Organization:       []string{"defaultOrganization"},
					Locality:           []string{"defaultLocality"},
					Province:           []string{"defaultProvince"},
					Country:            []string{"defaultCountry"},
					PostalCode:         []string{"defaultPostalCode"},
					StreetAddress:      []string{"defaultStreetAddress"},
				},
			},
			want: pkix.Name{
				CommonName:         "dummyCommonName",
				SerialNumber:       "dummySerialNumber",
				OrganizationalUnit: []string{"dummyOrganizationalUnit"},
				Organization:       []string{"dummyOrganization"},
				Locality:           []string{"dummyLocality"},
				Province:           []string{"dummyProvince"},
				Country:            []string{"dummyCountry"},
				PostalCode:         []string{"dummyPostalCode"},
				StreetAddress:      []string{"dummyStreetAddress"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := applyDefaultAttributes(tt.args.name, tt.args.defaultName); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ApplyDefaultAttributes() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTrimEmptyAttributeValue(t *testing.T) {
	type args struct {
		name pkix.Name
	}
	tests := []struct {
		name string
		args args
		want pkix.Name
	}{
		{
			name: "Trim empty attribute values",
			args: args{
				name: pkix.Name{
					CommonName:         "",
					SerialNumber:       "",
					OrganizationalUnit: []string{"", ""},
					Organization:       []string{"", ""},
					Locality:           []string{"", ""},
					Province:           []string{"", ""},
					Country:            []string{"", ""},
					PostalCode:         []string{"", ""},
					StreetAddress:      []string{"", ""},
				},
			},
			want: pkix.Name{},
		},
		{
			name: "Trim empty attribute values but keep non-empty attributes",
			args: args{
				name: pkix.Name{
					CommonName:         "CN",
					SerialNumber:       "SERIALNUMBER",
					OrganizationalUnit: []string{"", "OU", ""},
					Organization:       []string{"O", "", ""},
					Locality:           []string{"", "L", ""},
					Province:           []string{"ST", "", ""},
					Country:            []string{"", "C", ""},
					PostalCode:         []string{"POSTALCODE", "", ""},
					StreetAddress:      []string{"", "STREET", ""},
				},
			},
			want: pkix.Name{
				CommonName:         "CN",
				SerialNumber:       "SERIALNUMBER",
				OrganizationalUnit: []string{"OU"},
				Organization:       []string{"O"},
				Locality:           []string{"L"},
				Province:           []string{"ST"},
				Country:            []string{"C"},
				PostalCode:         []string{"POSTALCODE"},
				StreetAddress:      []string{"STREET"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := trimEmptyAttributeValue(tt.args.name); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("TrimEmptyAttributeValue() = %v, want %v", got, tt.want)
			}
		})
	}
}
