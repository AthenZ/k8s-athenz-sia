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

package config

import (
	"fmt"
	"strings"
	"testing"

	"github.com/AthenZ/k8s-athenz-sia/v3/pkg/util"
)

func TestIdentityConfigReloaderFormatting(t *testing.T) {
	tests := []struct {
		name     string
		reloader *util.CertReloader
		want     string
	}{
		{name: "nil", want: "Reloader:<nil> "},
		{name: "non-nil", reloader: &util.CertReloader{}, want: "Reloader:<redacted> "},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &IdentityConfig{Reloader: tt.reloader}
			// Match the configuration format used by the startup log.
			got := fmt.Sprintf("%+v", cfg)
			if !strings.Contains(got, tt.want) {
				t.Errorf("formatted config = %q, want it to contain %q", got, tt.want)
			}
		})
	}
}
