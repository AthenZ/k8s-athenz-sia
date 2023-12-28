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

package token

import (
	"unsafe"
)

type Token interface {
	Domain() string
	Role() string
	Raw() string

	// Expiry returns the expiry time of the token in seconds since Unix epoch.
	Expiry() int64

	// Size returns the number of bytes used by the token struct.
	Size() uint
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

func (t *RoleToken) Size() uint {
	structSize := uint(unsafe.Sizeof(*t))
	// unsafe.Sizeof() ONLY count the string struct, need to count the actual string block explicitly
	stringSize := len(t.domain) + len(t.role) + len(t.raw)
	return structSize + uint(stringSize)
}

// AccessToken stores access token
type AccessToken struct {
	domain string
	role   string
	raw    string
	scope  string
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

func (t *AccessToken) Scope() string {
	return t.scope
}

func (t *AccessToken) Size() uint {
	structSize := uint(unsafe.Sizeof(*t))
	// unsafe.Sizeof() ONLY count the string struct, need to count the actual string block explicitly
	stringSize := len(t.domain) + len(t.role) + len(t.raw) + len(t.scope)
	return structSize + uint(stringSize)
}
