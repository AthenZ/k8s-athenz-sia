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

import "strings"

type Type int

const (
	ACCESS_TOKEN Type = 1 << iota // 01
	ROLE_TOKEN                    // 10
)

func (mode Type) Has(t Type) bool {
	return mode&t == t
}

func (mode Type) Disable(t Type) Type {
	return mode &^ t
}

func (mode Type) Enable(t Type) Type {
	return mode | t
}

func newType(raw string) (t Type) {
	if raw == "" {
		return t
	}
	if strings.Contains(raw, "accesstoken") {
		t |= ACCESS_TOKEN
	}
	if strings.Contains(raw, "roletoken") {
		t |= ROLE_TOKEN
	}
	return t
}
