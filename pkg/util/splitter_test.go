//
// Copyright The Athenz Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package util

import "testing"

func TestDomainRoleSplitter(test *testing.T) {
	// referred to TestSplitRoleName()
	// https://github.com/AthenZ/athenz/blob/73b25572656f289cce501b4c2fe78f86656082e7/libs/go/sia/util/util_test.go#L30-L69
	delimiter := ":role."
	domain, role, err := DomainRoleSplitter("role", delimiter)
	if err == nil {
		test.Errorf("Invalid role was parsed successfully")
		return
	}

	if domain != "" || role != "" {
		test.Errorf("Should return empty domain and role")
		return
	}

	domain, role, err = DomainRoleSplitter("role:role2:role3", delimiter)
	if err == nil {
		test.Errorf("Invalid role was parsed successfully")
		return
	}

	if domain != "" || role != "" {
		test.Errorf("Should return empty domain and role")
		return
	}

	domain, role, err = DomainRoleSplitter("role:test", delimiter)
	if err == nil {
		test.Errorf("Invalid role was parsed successfully")
		return
	}

	if domain != "" || role != "" {
		test.Errorf("Should return empty domain and role")
		return
	}

	domain, role, err = DomainRoleSplitter("role:role.", delimiter)
	if err == nil {
		test.Errorf("Invalid role was parsed successfully")
		return
	}

	if domain != "" || role != "" {
		test.Errorf("Should return empty domain and role")
		return
	}

	domain, role, err = DomainRoleSplitter("domain:role.test.role", delimiter)
	if err != nil {
		test.Errorf("Unable to parse valid role name successfully")
		return
	}
	if domain != "domain" {
		test.Errorf("Domain field is not expected domain value")
		return
	}
	if role != "test.role" {
		test.Errorf("Role field is not expected test.role value")
		return
	}
}

