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
	"path/filepath"
	"runtime/metrics"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AthenZ/athenz/clients/go/zts"
	"github.com/cenkalti/backoff"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/AthenZ/k8s-athenz-sia/v3/pkg/config"
	"github.com/AthenZ/k8s-athenz-sia/v3/pkg/daemon"
	extutil "github.com/AthenZ/k8s-athenz-sia/v3/pkg/util"
	"github.com/AthenZ/k8s-athenz-sia/v3/third_party/log"
	"github.com/AthenZ/k8s-athenz-sia/v3/third_party/util"
)

type tokenService struct {
	shutdownChan chan struct{}
	shutdownWg   sync.WaitGroup

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

func New(ctx context.Context, idCfg *config.IdentityConfig) (error, daemon.Daemon) {
	if ctx.Err() != nil {
		log.Info("Skipped token provider initiation")
		return nil, nil
	}

	ts := &tokenService{
		shutdownChan: make(chan struct{}, 1),
	}

	// check initialization skip
	tt := newType(idCfg.TokenType)
	if idCfg.TokenServerAddr == "" || tt == 0 {
		log.Infof("Token server is disabled due to insufficient options: address[%s], roles[%s], token-type[%s]", idCfg.TokenServerAddr, idCfg.TargetDomainRoles, idCfg.TokenType)
		return nil, ts
	}

	// initialize token cache with placeholder
	tokenExpiryInSecond := int(idCfg.TokenExpiry.Seconds())
	accessTokenCache := NewLockedTokenCache("accesstoken")
	roleTokenCache := NewLockedTokenCache("roletoken")
	for _, dr := range idCfg.TargetDomainRoles {
		domain, role := dr.Domain, dr.Role
		if tt&mACCESS_TOKEN != 0 {
			accessTokenCache.Store(CacheKey{Domain: domain, Role: role, MaxExpiry: tokenExpiryInSecond}, &AccessToken{})
		}
		if tt&mROLE_TOKEN != 0 {
			roleTokenCache.Store(CacheKey{Domain: domain, Role: role, MinExpiry: tokenExpiryInSecond}, &RoleToken{})
		}
	}

	// TODO: take care of merge conflict
	ztsClient, err := newZTSClient(idCfg.KeyFile, idCfg.CertFile, idCfg.ServerCACert, idCfg.Endpoint)
	if err != nil {
		return err, nil
	}

	saService := extutil.ServiceAccountToService(idCfg.ServiceAccount)
	if saService == "" {
		// TODO: get service from svc cert
		// https://github.com/AthenZ/athenz/blob/73b25572656f289cce501b4c2fe78f86656082e7/libs/go/athenzutils/principal.go
		// func ExtractServicePrincipal(x509Cert x509.Certificate) (string, error)
	}

	// register prometheus metrics
	if err := prometheus.Register(accessTokenCache); err != nil {
		return err, nil
	}
	if err := prometheus.Register(roleTokenCache); err != nil {
		return err, nil
	}

	// setup token service
	ts.accessTokenCache = accessTokenCache
	ts.roleTokenCache = roleTokenCache
	ts.ztsClient = ztsClient
	ts.saService = saService
	ts.tokenRESTAPI = idCfg.TokenServerRESTAPI
	ts.tokenType = tt
	ts.tokenDir = idCfg.TokenDir
	ts.tokenRefresh = idCfg.TokenRefresh
	ts.tokenExpiryInSecond = tokenExpiryInSecond
	ts.roleAuthHeader = idCfg.RoleAuthHeader
	ts.useTokenServer = idCfg.UseTokenServer
	ts.shutdownDelay = idCfg.ShutdownDelay
	ts.shutdownTimeout = idCfg.ShutdownTimeout

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
		return nil, ts
	}
	tokenServer := &http.Server{
		Addr:      idCfg.TokenServerAddr,
		Handler:   newHandlerFunc(ts, idCfg.TokenServerTimeout),
		TLSConfig: nil,
	}
	if idCfg.TokenServerTLSCertPath != "" && idCfg.TokenServerTLSKeyPath != "" {
		tokenServer.TLSConfig, err = NewTLSConfig(idCfg.TokenServerTLSCAPath, idCfg.TokenServerTLSCertPath, idCfg.TokenServerTLSKeyPath)
		if err != nil {
			return err, nil
		}
	}
	ts.tokenServer = tokenServer

	return nil, ts
}

// Start starts the token server, refreshes tokens periodically and reports memory usage periodically
func (ts *tokenService) Start(ctx context.Context) error {
	if ctx.Err() != nil {
		log.Info("Skipped token provider start")
		return nil
	}

	// starts the token server
	if ts.tokenServer != nil {
		log.Infof("Starting token provider[%s]", ts.tokenServer.Addr)
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
				log.Fatalf("Failed to start token provider: %s", err.Error())
			}
			log.Info("Stopped token server")
		}()
	}

	// refreshes tokens periodically
	t := time.NewTicker(ts.tokenRefresh)
	ts.shutdownWg.Add(1)
	go func() {
		defer t.Stop()
		defer ts.shutdownWg.Done()

		for {
			log.Infof("Will refresh tokens after %s", ts.tokenRefresh.String())

			select {
			case <-ts.shutdownChan:
				log.Info("Stopped token provider daemon")
				return
			case <-t.C:
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
				ts.reportMemory()
			}
		}
	}()

	// TODO: check server running status
	ts.tokenServerRunning = true

	return nil
}

func (ts *tokenService) Shutdown() {
	log.Info("Initiating shutdown of token provider daemon ...")
	close(ts.shutdownChan)

	if ts.tokenServer != nil && ts.tokenServerRunning {
		time.Sleep(ts.shutdownDelay)
		ctx, cancel := context.WithTimeout(context.Background(), ts.shutdownTimeout)
		defer cancel()
		ts.tokenServer.SetKeepAlivesEnabled(false)
		if err := ts.tokenServer.Shutdown(ctx); err != nil {
			// graceful shutdown error or timeout should be fatal
			log.Errorf("Failed to shutdown token provider: %s", err.Error())
		}
	}

	// wait for graceful shutdown
	ts.shutdownWg.Wait()
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
		at, err := fetchAccessToken(d.ztsClient, key, d.saService)
		if err != nil {
			return err
		}
		d.accessTokenCache.Store(key, at)
		log.Debugf("Successfully received token from Athenz ZTS server: accessTokens(%s, len=%d)", key, len(at.Raw()))
		return nil
	}
	updateRoleToken := func(key CacheKey) error {
		rt, err := fetchRoleToken(d.ztsClient, key)
		if err != nil {
			return err
		}
		d.roleTokenCache.Store(key, rt)
		log.Debugf("Successfully received token from Athenz ZTS server: roleTokens(%s, len=%d)", key, len(rt.Raw()))
		return nil
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

	w := util.NewWriter()

	err := d.accessTokenCache.Range(func(k CacheKey, t Token) error {
		domain := t.Domain()
		role := t.Role()
		at := t.Raw()
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
