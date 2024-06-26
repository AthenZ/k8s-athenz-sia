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
	"os"
	"path/filepath"
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

	tokenRESTAPI        bool
	tokenType           mode
	tokenDir            string
	tokenRefresh        time.Duration
	tokenExpiryInSecond int
	roleAuthHeader      string

	useTokenServer     bool
	tokenServer        *http.Server
	tokenServerRunning bool

	shutdownDelay   time.Duration
	shutdownTimeout time.Duration
}

func New(ctx context.Context, idCfg *config.IdentityConfig) (daemon.Daemon, error) {
	if ctx.Err() != nil {
		log.Info("Skipped token provider initiation")
		return nil, nil
	}

	// initialize token cache with placeholder
	tt := newType(idCfg.TokenType)
	tokenExpiryInSecond := int(idCfg.TokenExpiry.Seconds())
	accessTokenCache := NewLockedTokenCache("accesstoken", idCfg.Namespace, idCfg.PodName)
	roleTokenCache := NewLockedTokenCache("roletoken", idCfg.Namespace, idCfg.PodName)
	for _, dr := range idCfg.TargetDomainRoles {
		domain, role := dr.Domain, dr.Role
		if tt&mACCESS_TOKEN != 0 {
			accessTokenCache.Store(CacheKey{Domain: domain, Role: role, MaxExpiry: tokenExpiryInSecond}, &AccessToken{})
		}
		if tt&mROLE_TOKEN != 0 {
			roleTokenCache.Store(CacheKey{Domain: domain, Role: role, MinExpiry: tokenExpiryInSecond}, &RoleToken{})
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
		tokenRESTAPI:        idCfg.TokenServerRESTAPI,
		tokenType:           tt,
		tokenDir:            idCfg.TokenDir,
		tokenRefresh:        idCfg.TokenRefresh,
		tokenExpiryInSecond: tokenExpiryInSecond,
		roleAuthHeader:      idCfg.RoleAuthHeader,
		useTokenServer:      idCfg.UseTokenServer,
		shutdownDelay:       idCfg.ShutdownDelay,
		shutdownTimeout:     idCfg.ShutdownTimeout,
	}

	// initialize tokens on mode=refresh or TOKEN_DIR is set
	if !idCfg.Init || idCfg.TokenDir != "" {
		errs := ts.updateTokenCaches(ctx, config.DEFAULT_MAX_ELAPSED_TIME_ON_INIT)
		// TODO: if cap(errs) == len(errs), implies all token updates failed, should be fatal
		for _, err := range errs {
			log.Errorf("Failed to refresh tokens after multiple retries: %s", err.Error())
		}
		if err := ts.writeFilesWithRetry(ctx, config.DEFAULT_MAX_ELAPSED_TIME_ON_INIT); err != nil {
			log.Errorf("Failed to write token files after multiple retries: %s", err.Error())
		}
	}

	// create token server
	if idCfg.Init {
		log.Infof("Token server is disabled for init mode: address[%s]", idCfg.TokenServerAddr)
		return ts, nil
	}
	if idCfg.TokenServerAddr == "" || tt == 0 {
		log.Infof("Token server is disabled due to insufficient options: address[%s], token-type[%s]", idCfg.TokenServerAddr, idCfg.TokenType)
		return ts, nil
	}
	tokenServer := &http.Server{
		Addr:      idCfg.TokenServerAddr,
		Handler:   newHandlerFunc(ts, idCfg.TokenServerTimeout),
		TLSConfig: nil,
	}
	if idCfg.TokenServerTLSCertPath != "" && idCfg.TokenServerTLSKeyPath != "" {
		tokenServer.TLSConfig, err = NewTLSConfig(idCfg.TokenServerTLSCAPath, idCfg.TokenServerTLSCertPath, idCfg.TokenServerTLSKeyPath)
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

		if err := daemon.WaitForServerReady(ts.tokenServer.Addr, ts.tokenServer.TLSConfig != nil); err != nil {
			log.Errorf("Failed to confirm token provider server ready: %s", err.Error())
			return err
		}
		ts.tokenServerRunning = true
	}

	// refreshes tokens periodically
	if ts.tokenRefresh > 0 {
		t := time.NewTicker(ts.tokenRefresh)
		ts.shutdownWg.Add(1)
		go func() {
			defer t.Stop()
			defer ts.shutdownWg.Done()

			for {
				log.Infof("Will refresh cached tokens within %s", ts.tokenRefresh.String())

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
					for _, err := range ts.updateTokenCaches(ctx, ts.tokenRefresh/4) {
						log.Errorf("Failed to refresh tokens after multiple retries: %s", err.Error())
					}
					// backoff retry until TOKEN_REFRESH_INTERVAL / 4 OR context is done
					if err := ts.writeFilesWithRetry(ctx, ts.tokenRefresh/4); err != nil {
						log.Errorf("Failed to write token files after multiple retries: %s", err.Error())
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

	if ts.tokenServer != nil && ts.tokenServerRunning {
		log.Infof("Delaying token provider server shutdown for %s to shutdown gracefully ...", ts.shutdownDelay.String())
		time.Sleep(ts.shutdownDelay)

		ctx, cancel := context.WithTimeout(context.Background(), ts.shutdownTimeout)
		defer cancel()
		ts.tokenServer.SetKeepAlivesEnabled(false)
		if err := ts.tokenServer.Shutdown(ctx); err != nil {
			// graceful shutdown error or timeout should be fatal
			log.Errorf("Failed to shutdown token provider server: %s", err.Error())
		}
	}

	// wait for graceful shutdown
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

	log.Debugf("Attempting to fetch %s from Athenz ZTS server: target[%s], requestID[%s]", tokenName, k.String(), requestID)

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

		log.Infof("Successfully updated %s cache: target[%s], requestID[%s]", tokenName, k.String(), requestID)
		return GroupDoResult{requestID: requestID, token: fetchedToken}, nil
	})

	result := r.(GroupDoResult)
	log.Debugf("requestID: [%s] handledRequestId: [%s] target: [%s]", requestID, result.requestID, k.String())

	if shared && result.requestID != requestID { // if it is shared and not the actual performer:
		if err == nil {
			log.Infof("Successfully updated %s cache by coalescing requests to a leader request: target[%s], leaderRequestID[%s], requestID[%s]", tokenName, k.String(), result.requestID, requestID)
		} else {
			log.Debugf("Failed to fetch %s while coalescing requests to a leader request: target[%s], leaderRequestID[%s], requestID[%s], err[%s]", tokenName, k.String(), result.requestID, requestID, err)
		}
	}

	return result, err
}

func (ts *tokenService) updateTokenCaches(ctx context.Context, maxElapsedTime time.Duration) []error {
	var atErrorCount, rtErrorCount atomic.Int64
	atTargets := ts.accessTokenCache.Keys()
	rtTargets := ts.roleTokenCache.Keys()
	log.Infof("Attempting to fetch tokens from Athenz ZTS server: access token targets[%v], role token targets[%v]...", atTargets, rtTargets)

	var wg sync.WaitGroup
	echan := make(chan error, len(atTargets)+len(rtTargets))

	for _, t := range atTargets {
		wg.Add(1)
		go func(key CacheKey) {
			defer wg.Done()
			err := ts.updateTokenWithRetry(ctx, maxElapsedTime, key, mACCESS_TOKEN)
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
			err := ts.updateTokenWithRetry(ctx, maxElapsedTime, key, mROLE_TOKEN)
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

func (ts *tokenService) updateTokenWithRetry(ctx context.Context, maxElapsedTime time.Duration, key CacheKey, tt mode) error {
	// backoff config with first retry delay of 5s, and then 10s, 20s, ...
	b := backoff.NewExponentialBackOff()
	b.InitialInterval = 5 * time.Second
	b.Multiplier = 2
	b.MaxElapsedTime = maxElapsedTime

	operation := func() error {
		return ts.updateToken(key, tt)
	}
	notifyOnErr := func(err error, backoffDelay time.Duration) {
		log.Errorf("Failed to refresh tokens: %s. Retrying in %s", err.Error(), backoffDelay)
	}
	return backoff.RetryNotify(operation, backoff.WithContext(b, ctx), notifyOnErr)
}

func (d *tokenService) updateToken(key CacheKey, tt mode) error {
	updateAccessToken := func(key CacheKey) error {
		_, err := d.requestTokenToZts(key, mACCESS_TOKEN, "daemon_access_token_update")
		return err
	}
	updateRoleToken := func(key CacheKey) error {
		_, err := d.requestTokenToZts(key, mROLE_TOKEN, "daemon_role_token_update")
		return err
	}

	switch tt {
	case mACCESS_TOKEN:
		return updateAccessToken(key)
	case mROLE_TOKEN:
		return updateRoleToken(key)
	default:
		return fmt.Errorf("Invalid token type: %d", tt)
	}
}

func (ts *tokenService) writeFilesWithRetry(ctx context.Context, maxElapsedTime time.Duration) error {
	// backoff config with first retry delay of 5s, and then 10s, 20s, ...
	b := backoff.NewExponentialBackOff()
	b.InitialInterval = 5 * time.Second
	b.Multiplier = 2
	b.MaxElapsedTime = maxElapsedTime

	return backoff.RetryNotify(ts.writeFiles, backoff.WithContext(b, ctx), func(err error, backoffDelay time.Duration) {
		log.Errorf("Failed to write token files: %s. Retrying in %s", err.Error(), backoffDelay)
	})
}

func (d *tokenService) writeFiles() error {
	if d.tokenDir == "" {
		log.Debugf("Skipping to write token files to directory[%s]", d.tokenDir)
		return nil
	}

	// Create the directory before saving tokens
	if err := os.MkdirAll(d.tokenDir, 0755); err != nil {
		return fmt.Errorf("unable to create directory for tokens: %w", err)
	}

	w := util.NewWriter()

	err := d.accessTokenCache.Range(func(k CacheKey, t Token) error {
		domain := t.Domain()
		role := t.Role()
		at := t.Raw()
		if at == "" {
			// skip placeholder token added during daemon creation
			return nil
		}

		log.Infof("[New Access Token] Domain: %s, Role: %s", domain, role)
		outPath := filepath.Join(d.tokenDir, domain+":role."+role+".accesstoken")
		log.Debugf("Saving Access Token[%d bytes] at %s", len(at), outPath)
		if err := w.AddBytes(outPath, 0644, []byte(at)); err != nil {
			return fmt.Errorf("unable to save access token: %w", err)
		}
		return nil
	})
	if err != nil {
		return err
	}
	err = d.roleTokenCache.Range(func(k CacheKey, t Token) error {
		domain := t.Domain()
		role := t.Role()
		rt := t.Raw()
		if rt == "" {
			// skip placeholder token added during daemon creation
			return nil
		}

		log.Infof("[New Role Token] Domain: %s, Role: %s", domain, role)
		outPath := filepath.Join(d.tokenDir, domain+":role."+role+".roletoken")
		log.Debugf("Saving Role Token[%d bytes] at %s", len(rt), outPath)
		if err := w.AddBytes(outPath, 0644, []byte(rt)); err != nil {
			return fmt.Errorf("unable to save role token: %w", err)
		}
		return nil
	})
	if err != nil {
		return err
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
