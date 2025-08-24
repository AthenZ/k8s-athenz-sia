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

package certificate

import (
	"github.com/AthenZ/k8s-athenz-sia/v3/pkg/config"
	extutil "github.com/AthenZ/k8s-athenz-sia/v3/pkg/util"
)

// validateAllPaths iterates thorough the following:
// - CopperArgos cert paths
// - CopperArgos key paths
// - CA cert file path
// and validates that all of them are valid file paths, using the extutil.ValidateFilePath()
// To see how each file is validated, see extutil.ValidateFilePath() file directly.

func validalidateAllPaths(idCfg *config.IdentityConfig) error {
	if idCfg.ServiceCert.LocalCert.Use {
		return nil
	}

	// TODO: Write a reason why LocalCert Mode does not require the cert path validation!!
	if idCfg.ServiceCert.LocalCert.Use {
		return nil
	}

	for _, certFile := range idCfg.ServiceCert.CopperArgos.Cert.Paths {
		if err := extutil.ValidateFilePath(certFile); err != nil {
			return err
		}
	}

	for _, keyFile := range idCfg.ServiceCert.CopperArgos.Key.Paths {
		if err := extutil.ValidateFilePath(keyFile); err != nil {
			return err
		}
	}

	return extutil.ValidateFilePath(idCfg.CaCertFile) // will return error if idCfg.CaCertFile is not a valid filepath
}
