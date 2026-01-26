// Copyright 2024 LY Corporation
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

package authorizer

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	authorizerd "github.com/AthenZ/athenz-authorizer/v5"
	"github.com/AthenZ/k8s-athenz-sia/v3/pkg/config"
	"github.com/AthenZ/k8s-athenz-sia/v3/pkg/daemon"
	"github.com/AthenZ/k8s-athenz-sia/v3/third_party/log"
)

type authorizerService struct {
	shutdownChan chan struct{}
	shutdownWg   sync.WaitGroup

	idCfg                   *config.IdentityConfig
	authorizerServer        *http.Server
	authorizerServerRunning bool
	authorizerDaemon        authorizerd.Authorizerd

	daemonCtx    context.Context
	daemonCancel context.CancelFunc
}

func New(ctx context.Context, idCfg *config.IdentityConfig) (daemon.Daemon, error) {
	if ctx.Err() != nil {
		log.Info("Skipped authorizer initiation")
		return nil, nil
	}

	as := &authorizerService{
		shutdownChan: make(chan struct{}, 1),
		idCfg:        idCfg,
	}

	// check initialization skip
	if idCfg.Init {
		log.Infof("Authorizer is disabled for init mode: address[%s]", idCfg.Authorizer.Addr)
		return as, nil
	}
	if !idCfg.Authorizer.Use {
		log.Infof("Authorizer is disabled with empty options: address[%s], domains[%s]",
			idCfg.Authorizer.Addr, idCfg.Authorizer.PolicyDomains)
		return as, nil
	}

	// Parse Athenz URL
	authorizerURL, err := url.Parse(idCfg.Endpoint)
	if err != nil {
		log.Errorf("Failed to parse url for authorizer from endpoint[%s]: %s", idCfg.Endpoint, err.Error())
		return nil, err
	}

	// Create HTTP client by manually constructing from handler's underlying client
	// We need to create a new client because the identityHandler's client field is unexported
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	if idCfg.ServerCACert != "" {
		certPool := x509.NewCertPool()
		caCert, err := os.ReadFile(idCfg.ServerCACert)
		if err != nil {
			return nil, err
		}
		certPool.AppendCertsFromPEM(caCert)
		tlsConfig.RootCAs = certPool
	}

	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig = tlsConfig

	authorizerClient := &http.Client{
		Transport: t,
		Timeout:   30 * time.Second,
	}

	// Initialize athenz-authorizer daemon
	authzDaemon, err := authorizerd.New(
		authorizerd.WithAthenzURL(authorizerURL.Host+authorizerURL.Path),
		authorizerd.WithHTTPClient(authorizerClient),
		authorizerd.WithAthenzDomains(strings.Split(idCfg.Authorizer.PolicyDomains, ",")...),
		authorizerd.WithPolicyRefreshPeriod(idCfg.Authorizer.PolicyRefreshInterval.String()),
		authorizerd.WithPubkeyRefreshPeriod(idCfg.Authorizer.PublicKeyRefreshInterval.String()),
		authorizerd.WithCacheExp(idCfg.Authorizer.CacheInterval),
		authorizerd.WithEnablePolicyd(),
		authorizerd.WithEnableJwkd(),
		authorizerd.WithAccessTokenParam(authorizerd.NewAccessTokenParam(
			true,
			idCfg.Authorizer.EnableMTLSCertificateBoundAccessToken,
			"", "", false, nil, "")),
		authorizerd.WithEnableRoleToken(),
		authorizerd.WithRoleAuthHeader(idCfg.Authorizer.RoleAuthHeader),
	)
	if err != nil {
		log.Errorf("Failed to initialize authorizer: %s", err.Error())
		return nil, err
	}
	as.authorizerDaemon = authzDaemon

	if err := as.authorizerDaemon.Init(ctx); err != nil {
		log.Errorf("Failed to initialize authorizer daemon: %s", err.Error())
		return nil, err
	}

	as.authorizerServer = &http.Server{
		Addr:    idCfg.Authorizer.Addr,
		Handler: http.HandlerFunc(as.handleAuthorizerRequest),
	}

	log.Infof("Initialized authorizer: address[%s], domains[%s]",
		idCfg.Authorizer.Addr, idCfg.Authorizer.PolicyDomains)

	return as, nil
}

// Start starts the authorizer server
func (as *authorizerService) Start(ctx context.Context) error {
	if ctx.Err() != nil {
		log.Info("Skipped authorizer start")
		return nil
	}

	if as.authorizerDaemon == nil || as.authorizerServer == nil {
		return nil
	}

	as.daemonCtx, as.daemonCancel = context.WithCancel(context.Background())

	// Start athenz-authorizer daemon
	as.shutdownWg.Add(1)
	go func() {
		defer as.shutdownWg.Done()
		log.Infof("Starting authorizer daemon: domains[%s]", as.idCfg.Authorizer.PolicyDomains)

		for err := range as.authorizerDaemon.Start(as.daemonCtx) {
			if err == context.Canceled || strings.Contains(err.Error(), "context canceled") {
				log.Debugf("Authorizer daemon stopped: %s", err.Error())
			} else {
				log.Errorf("Authorizer daemon error: %s", err.Error())
			}
		}
	}()

	// Start HTTP server
	as.shutdownWg.Add(1)
	go func() {
		defer as.shutdownWg.Done()
		log.Infof("Starting authorizer server[%s]", as.idCfg.Authorizer.Addr)

		if err := as.authorizerServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start authorizer server: %s", err.Error())
		}
		log.Info("Stopped authorizer server")
	}()

	if err := daemon.WaitForServerReady(as.authorizerServer.Addr, false, false); err != nil {
		log.Errorf("Failed to confirm authorizer server ready: %s", err.Error())
		return err
	}
	as.authorizerServerRunning = true

	return nil
}

func (as *authorizerService) Shutdown() {
	log.Info("Initiating shutdown of authorizer daemon ...")
	close(as.shutdownChan)

	if as.authorizerServer != nil {
		if as.authorizerServerRunning {
			log.Infof("Delaying authorizer server shutdown for %s to shutdown gracefully ...", "9s")
			time.Sleep(9 * time.Second)

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			as.authorizerServer.SetKeepAlivesEnabled(false)
			if err := as.authorizerServer.Shutdown(ctx); err != nil {
				// graceful shutdown error or timeout should be fatal
				log.Errorf("Failed to shutdown authorizer server gracefully: %s", err.Error())
			}
		} else {
			log.Info("Force shutdown authorizer server...")

			forcedCtx, cancel := context.WithCancel(context.Background())
			cancel() // force shutdown authorizer server without delay
			as.authorizerServer.SetKeepAlivesEnabled(false)
			if err := as.authorizerServer.Shutdown(forcedCtx); err != nil && err != context.Canceled {
				// forceful shutdown error
				log.Errorf("Failed to shutdown authorizer server forcefully: %s", err.Error())
			}
		}
	}

	if as.daemonCancel != nil {
		as.daemonCancel()
	}

	as.shutdownWg.Wait()
}

func (as *authorizerService) handleAuthorizerRequest(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if err := recover(); err != nil && err != http.ErrAbortHandler {
			const size = 64 << 10
			buf := make([]byte, size)
			buf = buf[:runtime.Stack(buf, false)]
			log.Errorf("http: panic serving %v: %v\n%s", r.RemoteAddr, err, buf)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}()

	// Extract headers
	action := r.Header.Get("X-Athenz-Action")
	resource := r.Header.Get("X-Athenz-Resource")

	accessTokenHeader := strings.Split(r.Header.Get("Authorization"), " ")
	at := accessTokenHeader[len(accessTokenHeader)-1]

	// Validate required headers
	if at == "" || action == "" || resource == "" {
		log.Infof("Required http headers are not set: Authorization len(%d), action[%s], resource[%s]",
			len(at), action, resource)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Authorize
	principal, err := as.authorizerDaemon.AuthorizeAccessToken(r.Context(), at, action, resource, nil)
	if err != nil || principal == nil {
		err = fmt.Errorf("authorization failed with access token, action[%s], resource[%s]: %w", action, resource, err)
		log.Debugf("Authorization failed: %s", err.Error())
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Set response headers
	w.Header().Set("x-athenz-principal", principal.Name())
	w.Header().Set("x-athenz-domain", principal.Domain())
	w.Header().Set("x-athenz-role", strings.Join(principal.Roles(), ","))
	w.Header().Set("x-athenz-issued-at", fmt.Sprintf("%d", principal.IssueTime()))
	w.Header().Set("x-athenz-expires-at", fmt.Sprintf("%d", principal.ExpiryTime()))
	w.Header().Set("x-athenz-authorized-role", strings.Join(principal.AuthorizedRoles(), ","))

	if c, ok := principal.(authorizerd.OAuthAccessToken); ok {
		w.Header().Set("x-athenz-client-id", c.ClientID())
	}

	w.WriteHeader(http.StatusOK)

	log.Debugf("successfully authorized request with Authorization len(%d), action[%s], resource[%s]", len(at), action, resource)
}
