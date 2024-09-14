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

// Package config defines all the configuration parameters. It reads configuration from environment variables and command-line arguments.
package config

import (
	"strings"

	"github.com/AthenZ/k8s-athenz-sia/v3/third_party/log"
)

// TODO: Reorder this later after logic is implemented:
type DerivedRoleCert struct {
	Use               bool         // if fetching role certificate is enabled (de facto standard)
	Dir               string       // directory to store role certificates. // TODO: This might be deleted later
	TargetDomainRoles []DomainRole // domain roles to fetch role certificates for
	Delimiter         string
	Format            string
	KeyFormat         string //  empty "" means no separate key file output feature enabled; key file format for your role cert if separate key file is required.
}

// derivedRoleCertConfig reads given configuration and sets the derived state of fetching role certificates related configuration.
func (idCfg *IdentityConfig) derivedRoleCertConfig() error {
	// default:
	idCfg.RoleCert.Use = false

	// TODO: Following log should come here after ServiceCert is done in derived-service-cert.go
	// TODO: log.Debugf("Skipping to prepare csr for role certificates with target roles[%s], output directory[%s]", idCfg.RoleCertTargetDomainRoles, idCfg.RoleCertDir)
	if len(idCfg.targetDomainRoles.roleCerts) == 0 {
		return nil // disabled
	}

	if idCfg.roleCertDir == "" {
		return nil // disabled
	}

	// Enabled from now on:
	dir := strings.TrimSuffix(idCfg.roleCertDir, "/") + "/" // making sure it always ends with `/`
	idCfg.RoleCert = DerivedRoleCert{
		Use:               true,
		Dir:               dir,
		TargetDomainRoles: idCfg.targetDomainRoles.roleCerts,
		Delimiter:         idCfg.roleCertFilenameDelimiter,
		Format:            dir + "/{{domain}}{{delimiter}}{{role}}.cert.pem",
		KeyFormat: func() string {
			if idCfg.roleCertKeyFileOutput {
				return dir + "/{{domain}}{{delimiter}}{{role}}.key.pem"
			}
			return "" // means no separate key file output feature enabled
		}(),
	}

	// if certificate provisioning is disabled (use external key) and splitting role certificate key file is disabled, role certificate and external key mismatch problem may occur when external key rotates.
	// error case: issue role certificate, rotate external key, mismatch period, issue role certificate, resolve, rotate external key, ...
	if idCfg.ProviderService == "" && !idCfg.roleCertKeyFileOutput {
		// if role certificate issuing is enabled, warn user about the mismatch problem
		log.Warnf("Rotating KEY_FILE[%s] may cause key mismatch with issued role certificate due to different rotation cycle. Please manually restart SIA when you rotate the key file.", idCfg.KeyFile)
	}

	return nil
}
