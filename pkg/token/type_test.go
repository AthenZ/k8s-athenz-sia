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

import (
	"testing"

	. "github.com/onsi/gomega"
)

func Test_newType(t *testing.T) {
	type args struct {
		raw string
	}
	tests := []struct {
		name string
		args args
		want mode
	}{
		{
			name: "Test newType with empty string",
			args: args{
				raw: "",
			},
			want: 0,
		},
		{
			name: "Test newType with nothing string",
			args: args{
				raw: "nothing",
			},
			want: 0,
		},
		{
			name: "Test newType containing accesstoken string",
			args: args{
				raw: "nothing+accesstoken",
			},
			want: 1,
		},
		{
			name: "Test newType containing roletoken string",
			args: args{
				raw: "nothing=roletoken",
			},
			want: 2,
		},
		{
			name: "Test newType containing both accesstoken and roletoken string",
			args: args{
				raw: "nothing=accesstoken+roletoken",
			},
			want: 3,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t) // wraps with gomega
			// test method
			got := newType(tt.args.raw)
			// assert result
			g.Expect(got).To(Equal(tt.want))
		})
	}
}
