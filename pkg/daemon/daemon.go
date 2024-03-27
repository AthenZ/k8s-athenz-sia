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

package daemon

import (
	"context"

	"github.com/AthenZ/k8s-athenz-sia/v3/pkg/config"
)

// NewDaemonFunc defines the New() function. New() creates and initializes the daemon synchronously. New should stop processing gracefully when the context is cancelled.
type NewDaemonFunc func(ctx context.Context, idCfg *config.IdentityConfig) (Daemon, error)

type Daemon interface {
	// Start starts the daemon and creates required background go routines synchronously
	Start(ctx context.Context) error

	// Shutdown shutdown the daemon gracefully and synchronously
	Shutdown()
}
