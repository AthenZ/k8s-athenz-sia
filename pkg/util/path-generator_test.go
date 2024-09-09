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
	"testing"
)

func TestGeneratePath(t *testing.T) {
	type args struct {
		namingFormat string
		domain       string
		role         string
		delimiter    string
	}
	tests := []struct {
		testCase string
		args     args
		want     string
		wantErr  string
	}{
		{
			testCase: "return success with valid input",
			args: args{
				namingFormat: "/var/run/athenz/rolecerts/{{domain}}{{delimiter}}{{role}}.cert.pem",
				domain:       "athenz",
				role:         "users",
				delimiter:    ":role.",
			},
			want:    "/var/run/athenz/rolecerts/athenz:role.users.cert.pem",
			wantErr: "",
		},
		{
			testCase: "return success with valid input, duplicate placeholder",
			args: args{
				namingFormat: "/var/run/athenz/{{domain}}/{{domain}}{{delimiter}}{{role}}.cert.pem",
				domain:       "athenz",
				role:         "users",
				delimiter:    ":role.",
			},
			want:    "/var/run/athenz/athenz/athenz:role.users.cert.pem",
			wantErr: "",
		},
		{
			testCase: "return error with empty naming format",
			args: args{
				namingFormat: "",
				domain:       "athenz",
				role:         "users",
				delimiter:    ":role.",
			},
			want:    "",
			wantErr: "naming format is empty",
		},
		{
			testCase: "return error with empty domain",
			args: args{
				namingFormat: "/var/run/athenz/rolecerts/{{domain}}{{delimiter}}{{role}}.cert.pem",
				domain:       "",
				role:         "users",
				delimiter:    ":role.",
			},
			want:    "",
			wantErr: "domain is empty",
		},
		{
			testCase: "return success with empty role, delimiter is discarded",
			args: args{
				namingFormat: "/var/run/athenz/rolecerts/{{domain}}{{delimiter}}{{role}}.cert.pem",
				domain:       "athenz",
				role:         "",
				delimiter:    ":role.",
			},
			want:    "/var/run/athenz/rolecerts/athenz.cert.pem",
			wantErr: "",
		},
		{
			testCase: "return error with invalid naming format, missing placeholder",
			args: args{
				namingFormat: "{{dummy}}",
				domain:       "athenz",
				role:         "users",
				delimiter:    ":role.",
			},
			want:    "",
			wantErr: "failed to parse naming format: template: pathGenerator:1: function \"dummy\" not defined",
		},
		{
			testCase: "return success with the placeholder test for {{.}} and {{.dummy}}, when referencing non-existent data, it results in an empty string.",
			args: args{
				namingFormat: "/var/run/athenz/rolecerts/{{.}}{{.dummy}}{{domain}}{{delimiter}}{{role}}.cert.pem",
				domain:       "athenz",
				role:         "users",
				delimiter:    ":role.",
			},
			want:    "/var/run/athenz/rolecerts/athenz:role.users.cert.pem",
			wantErr: "",
		},
	}

	for _, test := range tests {
		t.Run(test.testCase, func(t *testing.T) {
			got, err := GeneratePath(test.args.namingFormat, test.args.domain, test.args.role, test.args.delimiter)
			fmt.Println(got, err)
			if got != test.want {
				t.Errorf("GeneratePath() got = %v, want %v", got, test.want)
			}
			if err != nil || test.wantErr != "" {
				if err == nil || (test.wantErr != err.Error()) {
					t.Errorf("GeneratePath() err = %v, wantErr %v", err, test.wantErr)
				}
			}
		})
	}
}
