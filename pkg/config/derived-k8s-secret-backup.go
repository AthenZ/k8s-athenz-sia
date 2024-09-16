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
)

type DerivedK8sSecretBackup struct {
	Use      bool
	UseRead  bool
	UseWrite bool
	Secret   string // Secret name that your service cert is stored in
	Ns       string // Namespace that your Secret is stored in
}

// derivedK8sSecretBackupConfig // TODO: write me
func (idCfg *IdentityConfig) derivedK8sSecretBackupConfig() error {
	// default:
	idCfg.K8sSecretBackup = DerivedK8sSecretBackup{
		Use:      false,
		UseRead:  false,
		UseWrite: false,
		Secret:   "",
		Ns:       "",
	}

	if idCfg.CertSecret == "" {
		return nil // disabled
	}

	idCfg.K8sSecretBackup = DerivedK8sSecretBackup{
		Use:      true,
		UseRead:  strings.Contains(idCfg.backup, "read"),
		UseWrite: strings.Contains(idCfg.backup, "write"),
		Secret:   idCfg.CertSecret,
		Ns:       idCfg.Namespace,
	}
	return nil
}
