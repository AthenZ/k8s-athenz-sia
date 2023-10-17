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
	"fmt"
	"net/url"
	"strings"
)

const NS_DELIMITER = "-"
const DOMAIN_DELIMITER = "."

// NamespaceToDomain converts a kube namespace to an Athenz domain
func NamespaceToDomain(ns, pre, d, suf string) (domain string) {
	if d == "" {
		return pre + ns + suf
	}
	return pre + d + suf
}

// ServiceAccountToService converts a kube serviceaccount name to an Athenz service
func ServiceAccountToService(svc string) string {
	return svc
}

// ServiceSpiffeURI returns the SPIFFE URI for the specified Athens domain and service.
func ServiceSpiffeURI(domain, service string) (*url.URL, error) {
	return url.Parse(fmt.Sprintf("spiffe://%s/sa/%s", domain, service))
}

// RoleSpiffeURI returns the SPIFFE URI for the specified Athens domain and service.
func RoleSpiffeURI(domain, role string) (*url.URL, error) {
	return url.Parse(fmt.Sprintf("spiffe://%s/ra/%s", domain, role))
}

// DomainToDNSPart converts the Athenz domain into a DNS label
func DomainToDNSPart(domain string) (part string) {
	return strings.Replace(domain, ".", "-", -1)
}
