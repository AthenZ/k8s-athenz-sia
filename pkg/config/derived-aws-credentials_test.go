// Copyright 2026 LY Corporation
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
	"time"
)

const (
	testAWSTrustAnchor = "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/11111111-1111-1111-1111-111111111111"
	testAWSProfile     = "arn:aws:rolesanywhere:us-east-1:123456789012:profile/22222222-2222-2222-2222-222222222222"
)

func TestDerivedAWSCredentialsConfig(t *testing.T) {
	for _, tc := range []struct {
		name    string
		change  func(*IdentityConfig)
		wantUse bool
		wantErr bool
	}{
		{name: "enabled", wantUse: true},
		{name: "disabled", change: func(c *IdentityConfig) { c.AWSCredentials = AWSCredentialsConfig{} }},
		{name: "anchor only", change: func(c *IdentityConfig) { c.AWSCredentials.ProfileARN = "" }, wantErr: true},
		{name: "profile only", change: func(c *IdentityConfig) { c.AWSCredentials.TrustAnchorARN = "" }, wantErr: true},
		{name: "invalid ARN", change: func(c *IdentityConfig) { c.AWSCredentials.TrustAnchorARN = "invalid" }, wantErr: true},
		{name: "wrong resource", change: func(c *IdentityConfig) { c.AWSCredentials.ProfileARN = testAWSTrustAnchor }, wantErr: true},
		{name: "region mismatch", change: func(c *IdentityConfig) {
			c.AWSCredentials.ProfileARN = strings.Replace(testAWSProfile, "us-east-1", "us-west-2", 1)
		}, wantErr: true},
		{name: "account mismatch", change: func(c *IdentityConfig) {
			c.AWSCredentials.ProfileARN = strings.Replace(testAWSProfile, "123456789012", "210987654321", 1)
		}, wantErr: true},
		{name: "partition mismatch", change: func(c *IdentityConfig) {
			c.AWSCredentials.ProfileARN = strings.Replace(testAWSProfile, "arn:aws:", "arn:aws-cn:", 1)
		}, wantErr: true},
		{name: "no REST API", change: func(c *IdentityConfig) { c.tokenServerRESTAPI = false }, wantErr: true},
		{name: "no address", change: func(c *IdentityConfig) { c.tokenServerAddr = "" }, wantErr: true},
		{name: "no timeout", change: func(c *IdentityConfig) { c.tokenServerTimeout = 0 }, wantErr: true},
		{name: "init keeps shared settings", change: func(c *IdentityConfig) {
			c.Init, c.tokenServerRESTAPI, c.tokenServerAddr = true, false, ""
		}, wantUse: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := IdentityConfig{
				AWSCredentials:  AWSCredentialsConfig{TrustAnchorARN: testAWSTrustAnchor, ProfileARN: testAWSProfile},
				tokenServerAddr: "127.0.0.1:8080", tokenServerRESTAPI: true, tokenServerTimeout: 3 * time.Second,
			}
			if tc.change != nil {
				tc.change(&cfg)
			}
			if err := cfg.derivedAWSCredentialsConfig(); (err != nil) != tc.wantErr {
				t.Fatalf("error = %v, want error %v", err, tc.wantErr)
			}
			if cfg.AWSCredentials.Use != tc.wantUse {
				t.Fatalf("enabled = %v, want %v", cfg.AWSCredentials.Use, tc.wantUse)
			}
			if tc.wantUse && cfg.AWSCredentials.Region != "us-east-1" {
				t.Fatal("region was not derived from the trust anchor")
			}
			if err := cfg.derivedTokenServerConfig(); err != nil {
				t.Fatal(err)
			}
			if !tc.wantErr && cfg.TokenServer.Use != (tc.wantUse && !cfg.Init) {
				t.Fatal("AWS-only token server enablement is incorrect")
			}
		})
	}
}

func TestAWSCredentialsFlagsOverrideEnvironment(t *testing.T) {
	t.Setenv("AWS_TRUST_ANCHOR_ARN", "environment-anchor")
	t.Setenv("AWS_PROFILE_ARN", "environment-profile")
	cfg := DefaultIdentityConfig()
	if err := cfg.loadFromENV(); err != nil {
		t.Fatal(err)
	}
	if cfg.AWSCredentials.TrustAnchorARN != "environment-anchor" || cfg.AWSCredentials.ProfileARN != "environment-profile" {
		t.Fatal("AWS environment settings were not loaded")
	}
	if err := cfg.loadFromFlag("test", []string{"--aws-trust-anchor-arn", testAWSTrustAnchor, "--aws-profile-arn", testAWSProfile}); err != nil {
		t.Fatal(err)
	}
	if cfg.AWSCredentials.TrustAnchorARN != testAWSTrustAnchor || cfg.AWSCredentials.ProfileARN != testAWSProfile {
		t.Fatal("AWS flags did not override environment settings")
	}
}

func TestAWSCredentialsValidRoleARN(t *testing.T) {
	cfg := AWSCredentialsConfig{TrustAnchorARN: testAWSTrustAnchor}
	for _, role := range []string{"arn:aws:iam::123456789012:role/reader", "arn:aws:iam::123456789012:role/team/reader"} {
		if !cfg.ValidRoleARN(role) {
			t.Errorf("valid role rejected: %s", role)
		}
	}
	for _, role := range []string{"", "--debug", "arn:aws:iam::123456789012:user/reader", "arn:aws-cn:iam::123456789012:role/reader", "arn:aws:iam::123456789012:role/", "arn:aws:iam::123456789012:role/bad\nrole"} {
		if cfg.ValidRoleARN(role) {
			t.Errorf("invalid role accepted: %q", role)
		}
	}
}
