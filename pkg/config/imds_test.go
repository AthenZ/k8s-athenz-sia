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
	"strings"
	"testing"
)

func TestIMDSServerConfigurationPrecedence(t *testing.T) {
	t.Setenv("USE_IMDS_SERVER", "true")
	t.Setenv("IMDS_SERVER_ADDR", "127.0.0.1:1339")
	t.Setenv("IMDS_SOURCE", "file")
	t.Setenv("IMDS_ROLE", "from-env")
	t.Setenv("IMDS_CREDENTIALS_FILE", "/env/credentials")
	t.Setenv("IMDS_DOMAIN", "env-domain")
	t.Setenv("IMDS_DURATION_SECONDS", "900")

	cfg := DefaultIdentityConfig()
	if cfg.IMDSServer.Use || cfg.IMDSServer.Addr != "127.0.0.1:1338" {
		t.Fatalf("unexpected IMDS defaults: %+v", cfg.IMDSServer)
	}
	if err := cfg.loadFromENV(); err != nil {
		t.Fatal(err)
	}
	if !cfg.IMDSServer.Use || cfg.IMDSServer.Addr != "127.0.0.1:1339" ||
		cfg.IMDSServer.Source != "file" || cfg.IMDSServer.Role != "from-env" ||
		cfg.IMDSServer.CredentialsFile != "/env/credentials" ||
		cfg.IMDSServer.Domain != "env-domain" || cfg.IMDSServer.DurationSeconds != 900 {
		t.Fatalf("unexpected IMDS environment config: %+v", cfg.IMDSServer)
	}

	args := []string{
		"-use-imds-server=false", "-imds-server-addr=127.0.0.1:1340",
		"-imds-source=zts", "-imds-role=from-flag",
		"-imds-credentials-file=/flag/credentials", "-imds-domain=flag-domain",
		"-imds-duration-seconds=1800",
	}
	if err := cfg.loadFromFlag("athenz-sia", args); err != nil {
		t.Fatal(err)
	}
	if cfg.IMDSServer.Use || cfg.IMDSServer.Addr != "127.0.0.1:1340" ||
		cfg.IMDSServer.Source != "zts" || cfg.IMDSServer.Role != "from-flag" ||
		cfg.IMDSServer.CredentialsFile != "/flag/credentials" ||
		cfg.IMDSServer.Domain != "flag-domain" || cfg.IMDSServer.DurationSeconds != 1800 {
		t.Fatalf("unexpected IMDS flag config: %+v", cfg.IMDSServer)
	}
}

func TestIMDSServerConfigurationRejectsInvalidEnv(t *testing.T) {
	for _, tc := range []struct {
		name, env, value string
	}{
		{"enabled", "USE_IMDS_SERVER", "invalid"},
		{"duration", "IMDS_DURATION_SECONDS", "invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(tc.env, tc.value)
			cfg := DefaultIdentityConfig()
			if err := cfg.loadFromENV(); err == nil || !strings.Contains(err.Error(), tc.env) {
				t.Fatalf("expected %s error, got %v", tc.env, err)
			}
		})
	}
}
