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
		athenzDomain    string
		providerService string
		ServiceAccount  string
		certSubject     DerivedCertSubject
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
				athenzDomain:    "domain",
				providerService: "provider-service",
				ServiceAccount:  "sa",
				certSubject: DerivedCertSubject{
					serviceCert: pkix.Name{
						CommonName:         "",
						OrganizationalUnit: []string{"default"},
						Organization:       []string{"dummyOrganization"},
						Locality:           []string{"dummyLocality"},
						Province:           []string{"dummyProvince"},
						Country:            []string{"dummyCountry"},
						PostalCode:         []string{"dummyPostalCode"},
						StreetAddress:      []string{"dummyStreetAddress"},
					},
				},
			},
			want: &pkix.Name{
				CommonName:         "domain.sa",
				OrganizationalUnit: []string{"provider-service"},
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
			name: "Empty certSubject",
			fields: fields{
				athenzDomain:    "domain",
				providerService: "provider-service",
				ServiceAccount:  "sa",
				certSubject: DerivedCertSubject{
					serviceCert: pkix.Name{},
				},
			},
			want: &pkix.Name{
				CommonName:         "domain.sa",
				OrganizationalUnit: []string{"provider-service"},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idCfg := IdentityConfig{
				certFile:        "/tmp/cert.pem",
				keyFile:         "/tmp/key.pem",
				Namespace:       "",
				athenzPrefix:    "",
				athenzSuffix:    "",
				athenzDomain:    tt.fields.athenzDomain,
				providerService: tt.fields.providerService,
				ServiceAccount:  tt.fields.ServiceAccount,
				certSubject:     tt.fields.certSubject,
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
