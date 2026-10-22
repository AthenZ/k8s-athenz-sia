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

func TestCertReloaderFormatting(t *testing.T) {
	tests := []struct {
		name     string
		reloader *CertReloader
		want     string
	}{
		{name: "nil", want: "<nil>"},
		{name: "empty", reloader: &CertReloader{}, want: "<redacted>"},
		{
			name: "populated",
			reloader: &CertReloader{
				certPEM: []byte("dummy certificate data"),
				keyPEM:  []byte("dummy key data"),
			},
			want: "<redacted>",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, format := range []string{"%s", "%v", "%+v"} {
				if got := fmt.Sprintf(format, tt.reloader); got != tt.want {
					t.Errorf("format %q = %q, want %q", format, got, tt.want)
				}
			}
		})
	}
}
