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

// TODO: refactor this type together with other enum flags in config.go (MODE, TOKEN_TYPE, BACKUP)

package token

import "strings"

// mode contains the type of token(s) that the client is requesting
// 0 (0x00) => no role token or access token
// 1 (0x01) => access token
// 2 (0x10) => role token
// 3 (0x11) => access token + role token
type mode int

const (
	mACCESS_TOKEN mode = 1 << iota // 01
	mROLE_TOKEN                    // 10
)

// func (m mode) has(t mode) bool {
// 	return m&t == t
// }

// func (m mode) disable(t mode) mode {
// 	return m &^ t
// }

// func (m mode) enable(t mode) mode {
// 	return m | t
// }

func newType(raw string) (t mode) {
	if raw == "" {
		return t
	}
	if strings.Contains(raw, "accesstoken") {
		t |= mACCESS_TOKEN
	}
	if strings.Contains(raw, "roletoken") {
		t |= mROLE_TOKEN
	}
	return t
}
