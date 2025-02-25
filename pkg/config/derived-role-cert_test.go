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

func TestIdentityConfig_derivedRoleCertConfig_subject(t *testing.T) {
	type fields struct {
		rawRoleCertSubject string
	}
	tests := []struct {
		name    string
		fields  fields
		want    *pkix.Name
		wantErr bool
	}{
		{
			name: "Valid role cert subject",
			fields: fields{
				rawRoleCertSubject: "OU=dummyOrganizationalUnit,O=dummyOrganization,L=dummyLocality,ST=dummyProvince,C=dummyCountry,POSTALCODE=dummyPostalCode,STREET=dummyStreetAddress",
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
			name: "Empty rawRoleCertSubject",
			fields: fields{
				rawRoleCertSubject: "",
			},
			want: &pkix.Name{
				OrganizationalUnit: []string{"Athenz"},
			},
			wantErr: false,
		},
		{
			name: "Use default attribute value if not set",
			fields: fields{
				rawRoleCertSubject: "O=dummyOrganization",
			},
			want: &pkix.Name{
				OrganizationalUnit: []string{"Athenz"},
				Organization:       []string{"dummyOrganization"},
			},
			wantErr: false,
		},
		{
			name: "Override default attribute value if set empty explicitly",
			fields: fields{
				rawRoleCertSubject: "O=dummyOrganization,OU=",
			},
			want: &pkix.Name{
				OrganizationalUnit: []string{""},
				Organization:       []string{"dummyOrganization"},
			},
			wantErr: false,
		},
		{
			name: "Invalid rawRoleCertSubject",
			fields: fields{
				rawRoleCertSubject: "INVALID_DN",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "Non-empty SERIALNUMBER in rawRoleCertSubject",
			fields: fields{
				rawRoleCertSubject: "SERIALNUMBER=dummySerialNumber",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "Non-empty CN in rawRoleCertSubject",
			fields: fields{
				rawRoleCertSubject: "CN=dummyCommonName",
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idCfg := IdentityConfig{
				targetDomainRoles: DerivedTargetDomainRoles{
					roleCerts: []DomainRole{
						{Domain: "domain", Role: "role"},
					},
				},
				roleCertNamingFormat:    "format",
				roleCertKeyNamingFormat: "keyFormat",
				rawRoleCertSubject:      tt.fields.rawRoleCertSubject,
			}
			if err := idCfg.derivedRoleCertConfig(); (err != nil) != tt.wantErr {
				t.Errorf("IdentityConfig.derivedRoleCertConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
			got := idCfg.RoleCert.Subject
			if tt.want == nil {
				if got != nil {
					t.Errorf("IdentityConfig.derivedRoleCertConfig() = %+v, want %+v", got, tt.want)
				}
				return
			}
			if idCfg.RoleCert.Subject.String() != tt.want.String() {
				t.Errorf("IdentityConfig.derivedRoleCertConfig() = %+v, want %+v", got, tt.want)
			}
		})
	}
}
