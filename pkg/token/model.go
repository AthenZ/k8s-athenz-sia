// Copyright 2023 Yahoo Japan Corporation
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

package token

type Token interface {
	Domain() string
	Role() string
	Raw() string
	Expiry() int64
}

// RoleToken stores role token
type RoleToken struct {
	domain string
	role   string
	raw    string
	expiry int64
}

func (t *RoleToken) Domain() string {
	return t.domain
}

func (t *RoleToken) Role() string {
	return t.role
}

func (t *RoleToken) Raw() string {
	return t.raw
}

func (t *RoleToken) Expiry() int64 {
	return t.expiry
}

// AccessToken stores access token
type AccessToken struct {
	domain string
	role   string
	raw    string
	expiry int64
}

func (t *AccessToken) Domain() string {
	return t.domain
}

func (t *AccessToken) Role() string {
	return t.role
}

func (t *AccessToken) Raw() string {
	return t.raw
}

func (t *AccessToken) Expiry() int64 {
	return t.expiry
}
