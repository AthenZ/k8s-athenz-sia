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

package util

import (
	"net/url"
	"testing"

	. "github.com/onsi/gomega"
)

func TestNamespaceToDomain(t *testing.T) {
	type args struct {
		ns  string
		pre string
		d   string
		suf string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Test empty",
			args: args{},
			want: "",
		},
		{
			name: "Test use namespace",
			args: args{
				ns:  "namespace",
				pre: "prefix-",
				suf: "-suffix",
			},
			want: "prefix-namespace-suffix",
		},
		{
			name: "Test use domain",
			args: args{
				ns:  "namespace",
				pre: "prefix-",
				d:   "domain",
				suf: "-suffix",
			},
			want: "prefix-domain-suffix",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t) // wraps with gomega
			// test method
			got := NamespaceToDomain(tt.args.ns, tt.args.pre, tt.args.d, tt.args.suf)
			// assert result
			g.Expect(got).To(Equal(tt.want))
		})
	}
}

func TestServiceAccountToService(t *testing.T) {
	type args struct {
		svc string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Test empty",
			args: args{},
			want: "",
		},
		{
			name: "Test service account",
			args: args{
				svc: "service-account",
			},
			want: "service-account",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t) // wraps with gomega
			// test method
			got := ServiceAccountToService(tt.args.svc)
			// assert result
			g.Expect(got).To(Equal(tt.want))
		})
	}
}

func TestServiceSpiffeURI(t *testing.T) {
	type args struct {
		domain  string
		service string
	}
	tests := []struct {
		name    string
		args    args
		want    *url.URL
		wantErr bool
	}{
		{
			name: "Test empty",
			args: args{},
			want: &url.URL{
				Scheme: "spiffe",
				Host:   "",
				Path:   "/sa/",
			},
		},
		{
			name: "Test error",
			args: args{
				domain: " ",
			},
			wantErr: true,
		},
		{
			name: "Test service spiffe uri",
			args: args{
				domain:  "domain",
				service: "service",
			},
			want: &url.URL{
				Scheme: "spiffe",
				Host:   "domain",
				Path:   "/sa/service",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t) // wraps with gomega
			// test method
			got, err := ServiceSpiffeURI(tt.args.domain, tt.args.service)
			// assert result
			if tt.wantErr {
				g.Expect(err).To(HaveOccurred())
			}
			g.Expect(got).To(Equal(tt.want))
		})
	}
}

func TestRoleSpiffeURI(t *testing.T) {
	type args struct {
		domain string
		role   string
	}
	tests := []struct {
		name    string
		args    args
		want    *url.URL
		wantErr bool
	}{
		{
			name: "Test empty",
			args: args{},
			want: &url.URL{
				Scheme: "spiffe",
				Host:   "",
				Path:   "/ra/",
			},
		},
		{
			name: "Test error",
			args: args{
				domain: " ",
			},
			wantErr: true,
		},
		{
			name: "Test role spiffe uri",
			args: args{
				domain: "domain",
				role:   "role",
			},
			want: &url.URL{
				Scheme: "spiffe",
				Host:   "domain",
				Path:   "/ra/role",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t) // wraps with gomega
			// test method
			got, err := RoleSpiffeURI(tt.args.domain, tt.args.role)
			// assert result
			if tt.wantErr {
				g.Expect(err).To(HaveOccurred())
			}
			g.Expect(got).To(Equal(tt.want))
		})
	}
}

func TestDomainToDNSPart(t *testing.T) {
	type args struct {
		domain string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Test empty",
			args: args{},
			want: "",
		},
		{
			name: "Test top level domain",
			args: args{
				domain: "top",
			},
			want: "top",
		},
		{
			name: "Test sub-domain",
			args: args{
				domain: "top.sub",
			},
			want: "top-sub",
		},
		{
			name: "Test multi-level sub-domain",
			args: args{
				domain: "top.sub1.sub2.sub3",
			},
			want: "top-sub1-sub2-sub3",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t) // wraps with gomega
			// test method
			got := DomainToDNSPart(tt.args.domain)
			// assert result
			g.Expect(got).To(Equal(tt.want))
		})
	}
}
