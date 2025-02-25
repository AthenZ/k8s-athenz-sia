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
				CommonName:         "",
				SerialNumber:       "",
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
