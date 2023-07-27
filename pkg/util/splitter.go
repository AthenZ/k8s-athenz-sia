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
// lim	tations under the License.

package util

import (
	"fmt"
	"strings"
)

// DomainRoleSplitter splits given domainRole into domain and role, with given delimiter
func DomainRoleSplitter(domainRole, delimiter string) (domain, role string, err error) {
	// referred to SplitRoleName()
	// https://github.com/AthenZ/athenz/blob/73b25572656f289cce501b4c2fe78f86656082e7/libs/go/sia/util/util.go#L69-L78

	if delimiter == "" {
		return "", "", fmt.Errorf("invalid delimiter: '%s', expected len(delimiter) > 0", delimiter)
	}

	splittedDr := strings.Split(domainRole, ":role.")
	if len(splittedDr) != 2 || len(splittedDr[0]) == 0 || len(splittedDr[1]) == 0 {
		return "", "", fmt.Errorf("invalid role name: '%s', expected format {domain}{delimiter}.{role}", domainRole)
	}
	domain = splittedDr[0]
	role = splittedDr[1]
	return
}
