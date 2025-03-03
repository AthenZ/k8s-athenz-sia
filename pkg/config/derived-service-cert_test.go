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

func TestIdentityConfig_derivedServiceCertConfig_CopperArgosMode_Subject(t *testing.T) {
	type fields struct {
		rawCertSubject string
	}
	tests := []struct {
		name       string
		beforeFunc func()
		afterFunc  func()
		fields     fields
		want       *pkix.Name
		wantErr    bool
	}{
		{
			name: "Valid instance subject",
			fields: fields{
				rawCertSubject: "OU=dummyOrganizationalUnit,O=dummyOrganization,L=dummyLocality,ST=dummyProvince,C=dummyCountry,POSTALCODE=dummyPostalCode,STREET=dummyStreetAddress",
			},
			want: &pkix.Name{
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
			fields: fields{
				rawCertSubject: "",
			},
			want: &pkix.Name{
				// should not set default value, as OU=PROVIDER_SERVICE
				// OrganizationalUnit: []string{"Athenz"},
			},
			wantErr: false,
		},
		{
			name: "Use default attribute value if not set",
			beforeFunc: func() {
				DEFAULT_COUNTRY = "C"
				DEFAULT_PROVINCE = "CA"
				DEFAULT_ORGANIZATION = "Organization"
				DEFAULT_ORGANIZATIONAL_UNIT = "OrganizationalUnit"
			},
			afterFunc: func() {
				DEFAULT_COUNTRY = ""
				DEFAULT_PROVINCE = ""
				DEFAULT_ORGANIZATION = ""
				DEFAULT_ORGANIZATIONAL_UNIT = ""
			},
			fields: fields{
				rawCertSubject: "L=Locality",
			},
			want: &pkix.Name{
				Country:      []string{"C"},
				Province:     []string{"CA"},
				Organization: []string{"Organization"},
				// OrganizationalUnit: []string{"OrganizationalUnit"},
				Locality: []string{"Locality"},
			},
			wantErr: false,
		},
		{
			name: "Override default attribute value if set empty explicitly",
			beforeFunc: func() {
				DEFAULT_PROVINCE = "CA"
			},
			afterFunc: func() {
				DEFAULT_PROVINCE = ""
			},
			fields: fields{
				rawCertSubject: "O=dummyOrganization,ST=",
			},
			want: &pkix.Name{
				Province:     []string{""},
				Organization: []string{"dummyOrganization"},
			},
			wantErr: false,
		},
		{
			name: "Invalid rawCertSubject",
			fields: fields{
				rawCertSubject: "INVALID_DN",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "Non-empty SERIALNUMBER in rawCertSubject",
			fields: fields{
				rawCertSubject: "SERIALNUMBER=dummySerialNumber",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "Non-empty CN in rawCertSubject",
			fields: fields{
				rawCertSubject: "CN=dummyCommonName",
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idCfg := IdentityConfig{
				providerService: "provider-service",
				rawCertSubject:  tt.fields.rawCertSubject,
			}
			if tt.beforeFunc != nil {
				tt.beforeFunc()
			}
			if err := idCfg.derivedServiceCertConfig(); (err != nil) != tt.wantErr {
				t.Errorf("IdentityConfig.derivedServiceCertConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.afterFunc != nil {
				tt.afterFunc()
			}

			got := idCfg.ServiceCert.CopperArgos.Subject
			if tt.want == nil {
				if got != nil {
					t.Errorf("IdentityConfig.derivedServiceCertConfig() = %+v, want %+v", got, tt.want)
				}
				return
			}
			if idCfg.ServiceCert.CopperArgos.Subject.String() != tt.want.String() {
				t.Errorf("IdentityConfig.derivedServiceCertConfig() = %+v, want %+v", got, tt.want)
			}
		})
	}
}
