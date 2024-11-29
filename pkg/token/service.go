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

package token

import (
	"context"
	"fmt"
	"net/http"
	"runtime/metrics"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AthenZ/athenz/clients/go/zts"
	"github.com/cenkalti/backoff"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sync/singleflight"

	"github.com/AthenZ/k8s-athenz-sia/v3/pkg/config"
	"github.com/AthenZ/k8s-athenz-sia/v3/pkg/daemon"
	extutil "github.com/AthenZ/k8s-athenz-sia/v3/pkg/util"
	"github.com/AthenZ/k8s-athenz-sia/v3/third_party/log"
	"github.com/AthenZ/k8s-athenz-sia/v3/third_party/util"
)

type tokenService struct {
	shutdownChan chan struct{}
	shutdownWg   sync.WaitGroup

	group            singleflight.Group
	accessTokenCache TokenCache
	roleTokenCache   TokenCache

	// keyFile      string
	// certFile     string
	// serverCACert string
	// endpoint     string
	ztsClient *zts.ZTSClient
	saService string

	idCfg *config.IdentityConfig
	// TODO: move to derived token
	tokenExpiryInSecond int
	tokenType           mode

	tokenServer        *http.Server
	tokenServerRunning bool
}

func New(ctx context.Context, idCfg *config.IdentityConfig) (daemon.Daemon, error) {
	if ctx.Err() != nil {
		log.Info("Skipped token provider initiation")
		return nil, nil
	}
	// TODO: move to derived token file
	if !idCfg.TokenFile.AccessToken.Use {
		// When file output is disabled, the Dir settings for the access token and role token will all be empty strings.
		log.Debugf("Skipping to write access token files to directory with empty filename format[%s]", idCfg.TokenFile.AccessToken.Format)
	}
	if !idCfg.TokenFile.RoleToken.Use {
		// When file output is disabled, the Dir settings for the access token and role token will all be empty strings.
		log.Debugf("Skipping to write role token files to directory with empty filename format[%s]", idCfg.TokenFile.RoleToken.Format)
	}

	// initialize token cache with placeholder
	tt := newType(idCfg.TokenType)
	tokenExpiryInSecond := int(idCfg.TokenExpiry.Seconds())
	accessTokenCache := NewLockedTokenCache("accesstoken", idCfg.Namespace, idCfg.PodName)
	roleTokenCache := NewLockedTokenCache("roletoken", idCfg.Namespace, idCfg.PodName)
	for _, dr := range idCfg.TokenTargetDomainRoles {
		domain, role := dr.Domain, dr.Role
		// TODO: Rewrite the following if statement as "if tt.isAccessTokenEnabled()..."
		if tt&mACCESS_TOKEN != 0 {
			accessTokenCache.Store(CacheKey{Domain: domain, Role: role, MaxExpiry: tokenExpiryInSecond, WriteFileRequired: idCfg.TokenFile.AccessToken.Use}, &AccessToken{})
		}
		// TODO: Rewrite the following if statement as "if tt.isRoleTokenEnabled()..."
		if tt&mROLE_TOKEN != 0 {
			roleTokenCache.Store(CacheKey{Domain: domain, Role: role, MinExpiry: tokenExpiryInSecond, WriteFileRequired: idCfg.TokenFile.RoleToken.Use}, &RoleToken{})
		}
	}

	ztsClient, err := newZTSClient(idCfg.Reloader, idCfg.ServerCACert, idCfg.Endpoint)
	if err != nil {
		return nil, err
	}

	saService := extutil.ServiceAccountToService(idCfg.ServiceAccount)
	if saService == "" {
		// TODO: get service from svc cert
		// https://github.com/AthenZ/athenz/blob/73b25572656f289cce501b4c2fe78f86656082e7/libs/go/athenzutils/principal.go
		// func ExtractServicePrincipal(x509Cert x509.Certificate) (string, error)
	}

	// register prometheus metrics
	if err := prometheus.Register(accessTokenCache); err != nil {
		return nil, err
	}
	if err := prometheus.Register(roleTokenCache); err != nil {
		return nil, err
	}

	// setup token service
	ts := &tokenService{
		shutdownChan:        make(chan struct{}, 1),
		accessTokenCache:    accessTokenCache,
		roleTokenCache:      roleTokenCache,
		ztsClient:           ztsClient,
		saService:           saService,
		idCfg:               idCfg,
		tokenType:           tt,
		tokenExpiryInSecond: tokenExpiryInSecond,
	}

	// write tokens as files only if it is non-init mode OR TOKEN_DIR is set
	// If it is in refresh mode, when requesting tokens using the REST API for the domains and roles specified in TARGET_DOMAIN_ROLES,
	// the cache is updated to ensure a cache hit from the first request.
	// TODO: Maybe !idCfg.Init || idCfg.TokenFile.Use()
	if !idCfg.Init || idCfg.TokenFile.AccessToken.Use || idCfg.TokenFile.RoleToken.Use {
		errs := ts.updateTokenCachesAndWriteFiles(ctx, config.DEFAULT_MAX_ELAPSED_TIME_ON_INIT)
		for _, err := range errs {
			log.Errorf("Failed to refresh tokens after multiple retries: %s", err.Error())
		}
		if idCfg.Init && len(errs) != 0 {
			return nil, fmt.Errorf("Unable to write token files: %s deliberately fails to start if every token is not fetched during the init mode", config.APP_NAME)
		}
	}

	// create token server
	// TODO: move to derived token file
	if idCfg.Init {
		log.Infof("Token server is disabled for init mode: address[%s]", idCfg.TokenServer.Addr)
		return ts, nil
	}
	// TODO: move to derived token file
	if !idCfg.TokenServer.Use {
		log.Infof("Token server is disabled due to insufficient options: address[%s], token-type[%s]", idCfg.TokenServer.Addr, idCfg.TokenType)
		return ts, nil
	}
	tokenServer := &http.Server{
		Addr:      idCfg.TokenServer.Addr,
		Handler:   newHandlerFunc(ts, idCfg.TokenServer.ServerTimeout),
		TLSConfig: nil,
	}
	if idCfg.TokenServer.TLS.Use {
		tokenServer.TLSConfig, err = NewTLSConfig(idCfg.TokenServer.TLS.CAPath, idCfg.TokenServer.TLS.CertPath, idCfg.TokenServer.TLS.KeyPath)
		if err != nil {
			return nil, err
		}
	}
	ts.tokenServer = tokenServer

	return ts, nil
}

// Start starts the token server, refreshes tokens periodically and reports memory usage periodically
func (ts *tokenService) Start(ctx context.Context) error {
	if ctx.Err() != nil {
		log.Info("Skipped token provider start")
		return nil
	}

	// starts the token server
	if ts.tokenServer != nil {
		log.Infof("Starting token provider server[%s]", ts.tokenServer.Addr)
		ts.shutdownWg.Add(1)
		go func() {
			defer ts.shutdownWg.Done()

			listenAndServe := func() error {
				if ts.tokenServer.TLSConfig != nil {
					return ts.tokenServer.ListenAndServeTLS("", "")
				}
				return ts.tokenServer.ListenAndServe()
			}
			if err := listenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Failed to start token provider server: %s", err.Error())
			}
			log.Info("Stopped token provider server")
		}()

		if err := daemon.WaitForServerReady(ts.tokenServer.Addr, ts.idCfg.TokenServer.TLS.Use, ts.idCfg.TokenServer.TLS.CAPath != ""); err != nil {
			log.Errorf("Failed to confirm token provider server ready: %s", err.Error())
			return err
		}
		ts.tokenServerRunning = true
	}

	// refreshes tokens periodically
	if ts.idCfg.TokenRefresh > 0 {
		t := time.NewTicker(ts.idCfg.TokenRefresh)
		ts.shutdownWg.Add(1)
		go func() {
			defer t.Stop()
			defer ts.shutdownWg.Done()

			for {
				log.Infof("Will refresh cached tokens within %s", ts.idCfg.TokenRefresh.String())

				select {
				case <-ts.shutdownChan:
					log.Info("Stopped token provider daemon")
					return
				case <-t.C:
					// skip refresh if context is done but Shutdown() is not called
					if ctx.Err() != nil {
						log.Info("Skipped to refresh cached tokens")
						continue
					}

					// backoff retry until TOKEN_REFRESH_INTERVAL / 4 OR context is done
					for _, err := range ts.updateTokenCachesAndWriteFiles(ctx, ts.idCfg.TokenRefresh/4) {
						log.Errorf("Failed to refresh tokens after multiple retries: %s", err.Error())
					}
				}
			}
		}()
	}

	// reports memory usage periodically
	reportTicker := time.NewTicker(time.Minute)
	ts.shutdownWg.Add(1)
	go func() {
		defer reportTicker.Stop()
		defer ts.shutdownWg.Done()

		for {
			select {
			case <-ts.shutdownChan:
				log.Info("Stopped memory reporter daemon")
				return
			case <-reportTicker.C:
				// skip report if context is done but Shutdown() is not called
				if ctx.Err() != nil {
					continue
				}
				ts.reportMemory()
			}
		}
	}()

	return nil
}

func (ts *tokenService) Shutdown() {
	log.Info("Initiating shutdown of token provider daemon ...")
	close(ts.shutdownChan)

	if ts.tokenServer != nil {
		if ts.tokenServerRunning {
			log.Infof("Delaying token provider server shutdown for %s to shutdown gracefully ...", ts.idCfg.TokenServer.ShutdownDelay.String())
			time.Sleep(ts.idCfg.TokenServer.ShutdownDelay)

			ctx, cancel := context.WithTimeout(context.Background(), ts.idCfg.TokenServer.ShutdownTimeout)
			defer cancel()
			ts.tokenServer.SetKeepAlivesEnabled(false)
			if err := ts.tokenServer.Shutdown(ctx); err != nil {
				// graceful shutdown error or timeout should be fatal
				log.Errorf("Failed to shutdown token provider server gracefully: %s", err.Error())
			}
		} else {
			log.Info("Force shutdown token provider server...")

			forcedCtx, cancel := context.WithCancel(context.Background())
			cancel() // force shutdown token provider server without delay
			ts.tokenServer.SetKeepAlivesEnabled(false)
			if err := ts.tokenServer.Shutdown(forcedCtx); err != nil && err != context.Canceled {
				// forceful shutdown error
				log.Errorf("Failed to shutdown token provider server forcefully: %s", err.Error())
			}
		}
	}

	// wait for graceful/forceful shutdown
	ts.shutdownWg.Wait()
}

// GroupDoResult contains token and its requestID after singleFlight.group.Do()
type GroupDoResult struct {
	requestID string
	token     Token
}

// requestTokenToZts sends a request to ZTS server to fetch either role token or access token.
// for mode, it only accepts mROLE_TOKEN or mACCESS_TOKEN
// it also stores in cache for you after successful fetch.
func (ts *tokenService) requestTokenToZts(k CacheKey, m mode, requestID string) (GroupDoResult, error) {
	tokenName := "" // tokenName is used for logger (role token or access token only)
	isRoleTokenRequested := m == mROLE_TOKEN
	isAccessTokenRequested := m == mACCESS_TOKEN

	if isRoleTokenRequested {
		tokenName = "role token"
	} else if isAccessTokenRequested {
		tokenName = "access token"
	} else {
		return GroupDoResult{requestID: requestID, token: nil}, fmt.Errorf("Invalid mode: %d", m)
	}

	log.Debugf("Attempting to get %s from Athenz ZTS server: target[%s], requestID[%s]", tokenName, k.String(), requestID)

	r, err, shared := ts.group.Do(k.UniqueId(tokenName), func() (interface{}, error) {
		// define variables before request to ZTS
		var fetchedToken Token
		var err error

		if isRoleTokenRequested {
			fetchedToken, err = fetchRoleToken(ts.ztsClient, k)
		} else { // isAccessTokenRequested
			fetchedToken, err = fetchAccessToken(ts.ztsClient, k, ts.saService)
		}

		if err != nil {
			log.Debugf("Failed to fetch %s from Athenz ZTS server: target[%s], requestID[%s]", tokenName, k.String(), requestID)
			return GroupDoResult{requestID: requestID, token: nil}, err
		}

		if isRoleTokenRequested {
			ts.roleTokenCache.Store(k, fetchedToken)
		} else { // isAccessTokenRequested
			ts.accessTokenCache.Store(k, fetchedToken)
		}

		log.Infof("Successfully received %s and saved into token cache: target[%s], requestID[%s]", tokenName, k.String(), requestID)
		return GroupDoResult{requestID: requestID, token: fetchedToken}, nil
	})

	result := r.(GroupDoResult)
	log.Debugf("requestID: [%s] handledRequestId: [%s] target: [%s]", requestID, result.requestID, k.String())

	if shared && result.requestID != requestID { // if it is shared and not the actual performer:
		if err == nil {
			log.Debugf("Successfully updated %s cache by coalescing requests to a leader request: target[%s], leaderRequestID[%s], requestID[%s]", tokenName, k.String(), result.requestID, requestID)
		} else {
			log.Debugf("Failed to fetch %s while coalescing requests to a leader request: target[%s], leaderRequestID[%s], requestID[%s], err[%s]", tokenName, k.String(), result.requestID, requestID, err)
		}
	}

	return result, err
}

func (ts *tokenService) updateTokenCachesAndWriteFiles(ctx context.Context, maxElapsedTime time.Duration) []error {
	var atErrorCount, rtErrorCount atomic.Int64
	atTargets := ts.accessTokenCache.Keys()
	rtTargets := ts.roleTokenCache.Keys()
	log.Infof("Attempting to get tokens from Athenz ZTS server: access token targets[%v], role token targets[%v]...", atTargets, rtTargets)

	var wg sync.WaitGroup
	echan := make(chan error, len(atTargets)+len(rtTargets))

	for _, t := range atTargets {
		wg.Add(1)
		go func(key CacheKey) {
			defer wg.Done()
			err := ts.updateAndWriteFileTokenWithRetry(ctx, maxElapsedTime, key, mACCESS_TOKEN)
			if err != nil {
				echan <- err
				atErrorCount.Add(1)
			}
		}(t)
	}

	for _, t := range rtTargets {
		wg.Add(1)
		go func(key CacheKey) {
			defer wg.Done()
			err := ts.updateAndWriteFileTokenWithRetry(ctx, maxElapsedTime, key, mROLE_TOKEN)
			if err != nil {
				echan <- err
				rtErrorCount.Add(1)
			}
		}(t)
	}

	// wait for ALL token updates to complete
	wg.Wait()
	log.Infof("Token cache updated. accesstoken:success[%d],error[%d]; roletoken:success[%d],error[%d]", int64(len(atTargets))-atErrorCount.Load(), atErrorCount.Load(), int64(len(rtTargets))-rtErrorCount.Load(), rtErrorCount.Load())

	// collect errors
	close(echan)
	errs := make([]error, 0, len(atTargets)+len(rtTargets))
	for err := range echan {
		errs = append(errs, err)
	}
	return errs
}

func (ts *tokenService) updateAndWriteFileTokenWithRetry(ctx context.Context, maxElapsedTime time.Duration, key CacheKey, tt mode) error {
	operation := func() error {
		return ts.updateAndWriteFileToken(key, tt)
	}
	notifyOnErr := func(err error, backoffDelay time.Duration) {
		log.Errorf("Failed to refresh tokens: %s. Retrying in %s", err.Error(), backoffDelay)
	}
	return backoff.RetryNotify(operation, newExponentialBackOff(ctx, maxElapsedTime), notifyOnErr)
}

func (d *tokenService) updateAndWriteFileToken(key CacheKey, tt mode) error {
	updateAndWriteFileAccessToken := func(key CacheKey) error {
		_, err := d.requestTokenToZts(key, mACCESS_TOKEN, "daemon_access_token_update")
		if err != nil || !key.WriteFileRequired {
			return err
		}
		// File output processing
		domain, role := key.Domain, key.Role
		token := d.accessTokenCache.Load(key)
		if token == nil {
			return fmt.Errorf("failed to load access token from cache: %s", key.String())
		}
		outPath, err := extutil.GeneratePath(d.idCfg.TokenFile.AccessToken.Format, domain, role, d.idCfg.TokenFile.AccessToken.Delimiter)
		if err != nil {
			return fmt.Errorf("failed to generate path for access token with format [%s], domain [%s], role [%s], delimiter [%s]: %w", d.idCfg.TokenFile.AccessToken.Format, domain, role, d.idCfg.TokenFile.AccessToken.Delimiter, err)
		}
		return d.writeFile(token, outPath, mACCESS_TOKEN)
	}
	updateAndWriteFileRoleToken := func(key CacheKey) error {
		_, err := d.requestTokenToZts(key, mROLE_TOKEN, "daemon_role_token_update")
		if err != nil || !key.WriteFileRequired {
			return err
		}
		// File output processing
		domain, role := key.Domain, key.Role
		token := d.roleTokenCache.Load(key)
		if token == nil {
			return fmt.Errorf("failed to load role token from cache: %s", key.String())
		}
		outPath, err := extutil.GeneratePath(d.idCfg.TokenFile.RoleToken.Format, domain, role, d.idCfg.TokenFile.RoleToken.Delimiter)
		if err != nil {
			return fmt.Errorf("failed to generate path for role token with format [%s], domain [%s], role [%s], delimiter [%s]: %w", d.idCfg.TokenFile.RoleToken.Format, domain, role, d.idCfg.TokenFile.RoleToken.Delimiter, err)
		}

		return d.writeFile(token, outPath, mROLE_TOKEN)
	}
	switch tt {
	case mACCESS_TOKEN:
		return updateAndWriteFileAccessToken(key)
	case mROLE_TOKEN:
		return updateAndWriteFileRoleToken(key)
	default:
		return fmt.Errorf("Invalid token type: %d", tt)
	}
}

// writeFile outputs given token (AT or RT) as file
func (d *tokenService) writeFile(token Token, outPath string, tt mode) error {
	w := util.NewWriter()
	tokenType := ""
	switch tt {
	case mACCESS_TOKEN:
		tokenType = "Access"
	case mROLE_TOKEN:
		tokenType = "Role"
	default:
		return fmt.Errorf("invalid token type: %d", tt)
	}

	rawToken := token.Raw()
	if rawToken == "" {
		// skip placeholder token added during daemon creation
		return nil
	}

	// Create the directory before saving tokens
	if err := extutil.CreateDirectory(outPath); err != nil {
		return fmt.Errorf("unable to create directory for token: %w", err)
	}
	// Unlike the delimiter used for file names, the log output will use the Athenz standard delimiter ":role.":
	log.Infof("[New %s Token] Subject: %s:role.%s [%d bytes] in %s", tokenType, token.Domain(), token.Role(), len(rawToken), outPath)
	if err := w.AddBytes(outPath, 0644, []byte(rawToken)); err != nil {
		return fmt.Errorf("unable to save %s Token: %w", tokenType, err)
	}
	return w.Save()
}

func (ts *tokenService) reportMemory() {
	// gather golang metrics
	const sysMemMetric = "/memory/classes/total:bytes"                  // go_memstats_sys_bytes
	const heapMemMetric = "/memory/classes/heap/objects:bytes"          // go_memstats_heap_alloc_bytes
	const releasedHeapMemMetric = "/memory/classes/heap/released:bytes" // go_memstats_heap_released_bytes
	// https://pkg.go.dev/runtime/metrics#pkg-examples
	// https://github.com/prometheus/client_golang/blob/3f8bd73e9b6d1e20e8e1536622bd0fda8bb3cb50/prometheus/go_collector_latest.go#L32
	samples := make([]metrics.Sample, 3)
	samples[0].Name = sysMemMetric
	samples[1].Name = heapMemMetric
	samples[2].Name = releasedHeapMemMetric
	metrics.Read(samples)
	validSample := func(s metrics.Sample) float64 {
		name, value := s.Name, s.Value
		switch value.Kind() {
		case metrics.KindUint64:
			return float64(value.Uint64())
		case metrics.KindFloat64:
			return value.Float64()
		case metrics.KindBad:
			// Check if the metric is actually supported. If it's not, the resulting value will always have kind KindBad.
			panic(fmt.Sprintf("%q: metric is no longer supported", name))
		default:
			// Check if the metrics specification has changed.
			panic(fmt.Sprintf("%q: unexpected metric Kind: %v\n", name, value.Kind()))
		}
	}
	sysMemValue := validSample(samples[0])
	heapMemValue := validSample(samples[1])
	releasedHeapMemValue := validSample(samples[2])
	sysMemInUse := sysMemValue - releasedHeapMemValue

	// gather token cache metrics
	atcSize := ts.accessTokenCache.Size()
	atcLen := ts.accessTokenCache.Len()
	rtcSize := ts.roleTokenCache.Size()
	rtcLen := ts.roleTokenCache.Len()
	totalSize := atcSize + rtcSize
	totalLen := atcLen + rtcLen

	// report as log message
	toMB := func(f float64) float64 {
		return f / 1024 / 1024
	}
	log.Infof("system_memory_inuse[%.1fMB]; go_memstats_heap_alloc_bytes[%.1fMB]; accesstoken:cached_token_bytes[%.1fMB],entries[%d]; roletoken:cached_token_bytes[%.1fMB],entries[%d]; total:cached_token_bytes[%.1fMB],entries[%d]; cache_token_ratio:sys[%.1f%%],heap[%.1f%%]", toMB(sysMemInUse), toMB(heapMemValue), toMB(float64(atcSize)), atcLen, toMB(float64(rtcSize)), rtcLen, toMB(float64(totalSize)), totalLen, float64(totalSize)/sysMemInUse*100, float64(totalSize)/heapMemValue*100)

	// TODO: memory triggers
	// if mem > warn threshold, warning log
	// if mem > error threshold, binary heap dump, i.e. debug.WriteHeapDump(os.Stdout.Fd())
}

// newExponentialBackOff returns a backoff config with first retry delay of 5s. Allow cancel by context.
func newExponentialBackOff(ctx context.Context, maxElapsedTime time.Duration) backoff.BackOff {
	b := backoff.NewExponentialBackOff()
	b.InitialInterval = 5 * time.Second
	b.Multiplier = 2
	b.MaxElapsedTime = maxElapsedTime

	return backoff.WithContext(b, ctx)
}
