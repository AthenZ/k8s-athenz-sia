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
	"os"
	"path/filepath"

	"github.com/AthenZ/k8s-athenz-sia/v3/third_party/log"
)

// CreateDirectory creates the necessary directories for file output from the specified file path for the output token or certificate.
func CreateDirectory(path string) error {
	dir := filepath.Dir(path)
	_, err := os.Stat(dir)
	if err == nil {
		return nil // directory already exists
	}

	if !os.IsNotExist(err) { // if it is not related to directory not found
		return fmt.Errorf("unable to check directory: %w", err)
	}

	log.Debugf("Creating new directory: %s", dir)
	err = os.MkdirAll(dir, 0755) // create directory
	if err != nil {
		return fmt.Errorf("unable to create directory: %w", err)
	}
	return nil // directory created successfully
}
