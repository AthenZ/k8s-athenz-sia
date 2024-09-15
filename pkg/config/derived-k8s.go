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

import "net"

type Pod struct {
	Ip  net.IP
	Uid string
	// Name string
}

type Secret struct {
	BackupCert string
}

type DerivedK8s struct {
	Ns     string // Namespace
	Sa     string // Service Account
	Pod    Pod    // Pod
	Secret Secret // Secret
}

// derivedK8sConfig reads given configuration and sets the derived state of k8s-related configuration.
func (idCfg *IdentityConfig) derivedK8sConfig() error {

	idCfg.K8s = DerivedK8s{
		Ns: idCfg.namespace,
		Sa: idCfg.serviceAccount,
		Pod: Pod{
			Ip:  idCfg.podIP,
			Uid: idCfg.podUID,
		},
		Secret: Secret{
			BackupCert: idCfg.certSecret,
		},
	}

	return nil
}
