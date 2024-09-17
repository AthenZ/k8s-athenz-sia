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
	"fmt"
	"path/filepath"

	"github.com/AthenZ/k8s-athenz-sia/v3/third_party/log"
)

type DerivedRoleCert struct {
	Use               bool         // if fetching role certificate is enabled (de facto standard)
	TargetDomainRoles []DomainRole // domain roles to fetch role certificates for
	Format            string       // format for role certificate file output (i.e. /var/run/athenz/rolecerts/{{domain}}:role.{{role}}.cert.pem).
	// format for role certificate key file output (i.e. /var/run/athenz/rolecerts/{{domain}}:role.{{role}}.key.pem)
	// empty "" means no separate key file output feature enabled.
	KeyFormat string
	Delimiter string // delimiter to separate domain and role name in the file name.
}

// derivedRoleCertConfig reads given configuration and sets the derived state of fetching role certificates related configuration.
func (idCfg *IdentityConfig) derivedRoleCertConfig() error {
	// default:
	idCfg.RoleCert.Use = false

	// TODO: Following log should come here after ServiceCert is done in derived-service-cert.go
	// TODO: log.Infof("Role certificate provisioning is disabled with empty options: roles[%s], output directory[%s]", idCfg.RoleCert.TargetDomainRoles, idCfg.RoleCert.Dir)
	if len(idCfg.targetDomainRoles.roleCerts) == 0 {
		return nil // disabled
	}

	if idCfg.roleCertDir == "" && idCfg.roleCertNamingFormat == "" {
		return nil // disabled
	}
	// If both the RoleCert settings and the NamingFormat settings are configured redundantly, an error will be returned.
	if idCfg.roleCertDir != "" && idCfg.roleCertNamingFormat != "" {
		return fmt.Errorf("Both ROLECERT_DIR[%s] and ROLE_CERT_NAMING_FORMAT[%s] are set. Please ensure only one of these is specified to avoid conflicts.", idCfg.roleCertDir, idCfg.roleCertNamingFormat)
	}
	if idCfg.roleCertDir != "" && idCfg.roleCertKeyNamingFormat != "" {
		return fmt.Errorf("Both ROLECERT_DIR[%s] and ROLE_CERT_KEY_NAMING_FORMAT[%s] are set. Please ensure only one of these is specified to avoid conflicts.", idCfg.roleCertDir, idCfg.roleCertKeyNamingFormat)
	}
	// If RoleCertKeyFileOutput is enabled, RoleCertKeyNamingFormat or RoleCertDir must be set.
	if idCfg.roleCertKeyFileOutput && idCfg.roleCertKeyNamingFormat == "" && idCfg.roleCertDir == "" {
		return fmt.Errorf("ROLE_CERT_KEY_FILE_OUTPUT[%t] is enabled but ROLE_CERT_KEY_NAMING_FORMAT[%s] and ROLECERT_DIR[%s] are not set. Please ensure that either ROLE_CERT_KEY_NAMING_FORMAT or ROLECERT_DIR is set.", idCfg.roleCertKeyFileOutput, idCfg.roleCertKeyNamingFormat, idCfg.roleCertDir)
	}

	// Enabled from now on:
	idCfg.RoleCert = DerivedRoleCert{
		Use:               true,
		TargetDomainRoles: idCfg.targetDomainRoles.roleCerts,
		Format: func() string {
			if idCfg.roleCertDir == "" {
				return idCfg.roleCertNamingFormat
			}
			return filepath.Join(idCfg.roleCertDir, "{{domain}}{{delimiter}}{{role}}"+".cert.pem")
		}(),
		KeyFormat: func() string {
			if idCfg.roleCertDir == "" {
				return idCfg.roleCertKeyNamingFormat
			}
			// If only RoleCertDir is defined, fixed values will be assigned to format and keyFormat:
			if idCfg.roleCertKeyFileOutput {
				return filepath.Join(idCfg.roleCertDir, "{{domain}}{{delimiter}}{{role}}"+".key.pem")
			}
			return "" // means no separate key file output feature enabled
		}(),
		Delimiter: idCfg.roleCertFilenameDelimiter,
	}

	// if certificate provisioning is disabled (use external key) and splitting role certificate key file is disabled, role certificate and external key mismatch problem may occur when external key rotates.
	// error case: issue role certificate, rotate external key, mismatch period, issue role certificate, resolve, rotate external key, ...
	if !idCfg.ServiceCert.CopperArgos.Use && idCfg.RoleCert.KeyFormat == "" {
		// if role certificate issuing is enabled, warn user about the mismatch problem
		log.Warnf("Rotating KEY_FILE[%s] may cause key mismatch with issued role certificate due to different rotation cycle. Please manually restart SIA when you rotate the key file.", idCfg.KeyFile)
	}

	return nil
}
