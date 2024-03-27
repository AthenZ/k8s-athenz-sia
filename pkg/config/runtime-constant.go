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
	"os"
	"path/filepath"
)

var (
	// VERSION is a constant storing the SIA version, provided by the build argument in go build
	VERSION string

	// VERSION is a constant storing the SIA build date, provided by the build argument in go build
	BUILD_DATE string

	// APP_NAME is a constant storing the binary name, provided by the command line
	APP_NAME = filepath.Base(os.Args[0])

	// USER_AGENT is a constant storing the User-Agent Header value, computed on package loading
	USER_AGENT = fmt.Sprintf("%s/%s", APP_NAME, VERSION)
)
