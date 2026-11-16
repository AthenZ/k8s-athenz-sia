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
	"regexp"
	"strings"
)

// AWSCredentialsConfig reuses the service certificate and token server settings.
// Region is derived from the trust anchor ARN, rather than configured separately.
type AWSCredentialsConfig struct {
	TrustAnchorARN string
	ProfileARN     string
	Region         string
	Use            bool
}

var rolesAnywhereARN = regexp.MustCompile(`^arn:(aws[a-z-]*):rolesanywhere:([a-z0-9-]+):([0-9]{12}):(trust-anchor|profile)/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$`)

func (idCfg *IdentityConfig) derivedAWSCredentialsConfig() error {
	cfg := &idCfg.AWSCredentials
	cfg.Use, cfg.Region = false, ""
	if cfg.TrustAnchorARN == "" && cfg.ProfileARN == "" {
		return nil
	}
	anchor := rolesAnywhereARN.FindStringSubmatch(cfg.TrustAnchorARN)
	profile := rolesAnywhereARN.FindStringSubmatch(cfg.ProfileARN)
	if anchor == nil || anchor[4] != "trust-anchor" {
		return fmt.Errorf("AWS_TRUST_ANCHOR_ARN must be an IAM Roles Anywhere trust anchor ARN")
	}
	if profile == nil || profile[4] != "profile" {
		return fmt.Errorf("AWS_PROFILE_ARN must be an IAM Roles Anywhere profile ARN")
	}
	if anchor[1] != profile[1] || anchor[2] != profile[2] || anchor[3] != profile[3] {
		return fmt.Errorf("AWS trust anchor and profile must have the same partition, region and account")
	}
	if !idCfg.Init && (idCfg.tokenServerAddr == "" || !idCfg.tokenServerRESTAPI || idCfg.tokenServerTimeout <= 0) {
		return fmt.Errorf("AWS credentials require token-server-addr, token-server-rest-api and a positive token-server-timeout in refresh mode")
	}
	cfg.Region, cfg.Use = anchor[2], true
	return nil
}

var iamRoleARN = regexp.MustCompile(`^arn:(aws[a-z-]*):iam::[0-9]{12}:role/([\x21-\x7e]*/)?[A-Za-z0-9_+=,.@-]{1,64}$`)

// ValidRoleARN checks the ARN shape and partition. AWS enforces profile and IAM permissions.
func (cfg AWSCredentialsConfig) ValidRoleARN(role string) bool {
	match := iamRoleARN.FindStringSubmatch(role)
	return len(role) <= 2048 && match != nil && strings.HasPrefix(cfg.TrustAnchorARN, "arn:"+match[1]+":")
}
