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
		wantErr bool
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
			wantErr: false,
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
			wantErr: false,
		},
		{
			name: "Multi-value attribute rawCertSubject",
			fields: fields{
				rawCertSubject: "OU=,OU=1,OU=2",
			},
			want: pkix.Name{
				OrganizationalUnit: []string{"1", "2"},
			},
			wantErr: false,
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
			wantErr: false,
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
			wantErr: false,
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
			wantErr: false,
		},
		{
			name: "Invalid rawCertSubject",
			fields: fields{
				rawCertSubject: "INVALID_DN",
			},
			want:    pkix.Name{},
			wantErr: true,
		},
		{
			name: "Non-empty SERIALNUMBER in rawCertSubject",
			fields: fields{
				rawCertSubject: "SERIALNUMBER=dummySerialNumber",
			},
			want:    pkix.Name{},
			wantErr: true,
		},
		{
			name: "Non-empty CN in rawCertSubject",
			fields: fields{
				rawCertSubject: "CN=dummyCommonName",
			},
			want:    pkix.Name{},
			wantErr: true,
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
			if err := idCfg.derivedCertSubject(); (err != nil) != tt.wantErr {
				t.Errorf("IdentityConfig.derivedCertSubject() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.after != nil {
				tt.after()
			}

			// assert equal
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

// assert independent
// serviceCert.Province = append(serviceCert.Province, "independent")
//
//	if reflect.DeepEqual(roleCert, serviceCert) {
//		t.Errorf("IdentityConfig.derivedCertSubject() pointing to same struct in roleCert = %+v, serviceCert = %+v", roleCert, serviceCert)
//	}
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
			name: "Set serviceCert independent from roleCert",
			fields: fields{
				rawCertSubject: "OU=dummyOrganizationalUnit,O=dummyOrganization,L=dummyLocality,ST=dummyProvince,C=dummyCountry,POSTALCODE=dummyPostalCode,STREET=dummyStreetAddress",
			},
			after: func(got *DerivedCertSubject) {
				got.roleCert.OrganizationalUnit[0] = "independent"
				got.serviceCert.Organization[0] = "independent"
				got.roleCert.Locality[0] = "independent"
				got.serviceCert.Province[0] = "independent"
				got.roleCert.Country[0] = "independent"
				got.serviceCert.PostalCode[0] = "independent"
				got.roleCert.StreetAddress[0] = "independent"
			},
			want: DerivedCertSubject{
				roleCert: pkix.Name{
					OrganizationalUnit: []string{"independent"},
					Organization:       []string{"dummyOrganization"},
					Locality:           []string{"independent"},
					Province:           []string{"dummyProvince"},
					Country:            []string{"independent"},
					PostalCode:         []string{"dummyPostalCode"},
					StreetAddress:      []string{"independent"},
				},
				serviceCert: pkix.Name{
					OrganizationalUnit: []string{"dummyOrganizationalUnit"},
					Organization:       []string{"independent"},
					Locality:           []string{"dummyLocality"},
					Province:           []string{"independent"},
					Country:            []string{"dummyCountry"},
					PostalCode:         []string{"independent"},
					StreetAddress:      []string{"dummyStreetAddress"},
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
