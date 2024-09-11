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
	"html/template"
	"strings"
)

// GeneratePath generates the output path for the credentials by applying the domain name, role name, and delimiter to a specified naming format.
// i.e) namingFormat=="/var/run/athenz/rolecerts/{{domain}}{{delimiter}}{{role}}"
func GeneratePath(namingFormat, domain, role, delimiter string) (string, error) {
	if namingFormat == "" {
		return "", fmt.Errorf("naming format is empty")
	}
	if domain == "" {
		return "", fmt.Errorf("domain is empty")
	}
	// If the role is an empty string, the delimiter used to separate the domain name and the role name is discarded as not necessary
	// i.e) domain="athenz", role="" => User wants to fetch tokens directly associated to the domain.
	if role == "" {
		delimiter = ""
	}
	funcMap := template.FuncMap{
		"domain":    func() string { return domain },
		"role":      func() string { return role },
		"delimiter": func() string { return delimiter },
	}

	generator, err := template.New("pathGenerator").Funcs(funcMap).Parse(namingFormat)
	if err != nil {
		return "", fmt.Errorf("failed to parse naming format: %v", err)
	}

	var writer strings.Builder
	if err := generator.Execute(&writer, nil); err != nil {
		return "", fmt.Errorf("failed to generate path: %v", err)
	}
	return writer.String(), nil
}
