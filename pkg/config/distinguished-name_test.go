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
	"reflect"
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
			if got := ApplyDefaultAttributes(tt.args.name, tt.args.defaultName); !reflect.DeepEqual(got, tt.want) {
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
			if got := TrimEmptyAttributeValue(tt.args.name); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("TrimEmptyAttributeValue() = %v, want %v", got, tt.want)
			}
		})
	}
}
