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
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/AthenZ/k8s-athenz-sia/v3/pkg/config"
	extutil "github.com/AthenZ/k8s-athenz-sia/v3/pkg/util"
	"github.com/AthenZ/k8s-athenz-sia/v3/third_party/log"
	"github.com/AthenZ/k8s-athenz-sia/v3/third_party/util"
)

type daemon struct {
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

	useTokenServer bool
}

func newDaemon(idConfig *config.IdentityConfig, tt mode) (*daemon, error) {

	// initialize token cache with placeholder
	tokenExpiryInSecond := int(idConfig.TokenExpiry.Seconds())
	accessTokenCache := NewLockedTokenCache("accesstoken")
	roleTokenCache := NewLockedTokenCache("roletoken")
	for _, dr := range idConfig.TargetDomainRoles {
		domain, role := dr.Domain, dr.Role
		if tt&mACCESS_TOKEN != 0 {
			accessTokenCache.Store(CacheKey{Domain: domain, Role: role, MaxExpiry: tokenExpiryInSecond}, &AccessToken{})
		}
		if tt&mROLE_TOKEN != 0 {
			roleTokenCache.Store(CacheKey{Domain: domain, Role: role, MinExpiry: tokenExpiryInSecond}, &RoleToken{})
		}
	}

	// register prometheus metrics
	promauto.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "cached_token_bytes",
		Help: "Number of bytes cached.",
		ConstLabels: prometheus.Labels{
			"type": "accesstoken",
		},
	}, func() float64 {
		return float64(accessTokenCache.Size())
	})
	promauto.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "cached_token_bytes",
		Help: "Number of bytes cached.",
		ConstLabels: prometheus.Labels{
			"type": "roletoken",
		},
	}, func() float64 {
		return float64(roleTokenCache.Size())
	})
	promauto.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "cached_token_entries",
		Help: "Number of entries cached.",
		ConstLabels: prometheus.Labels{
			"type": "accesstoken",
		},
	}, func() float64 {
		return float64(accessTokenCache.Len())
	})
	promauto.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "cached_token_entries",
		Help: "Number of entries cached.",
		ConstLabels: prometheus.Labels{
			"type": "roletoken",
		},
	}, func() float64 {
		return float64(roleTokenCache.Len())
	})

	var err error
	err = prometheus.Register(accessTokenCache)
	if err != nil {
		return nil, err
	}

	err = prometheus.Register(roleTokenCache)
	if err != nil {
		return nil, err
	}

	ztsClient, err := newZTSClient(idConfig.KeyFile, idConfig.CertFile, idConfig.ServerCACert, idConfig.Endpoint)
	if err != nil {
		return nil, err
	}

	saService := extutil.ServiceAccountToService(idConfig.ServiceAccount)
	if saService == "" {
		// TODO: get service from svc cert
		// https://github.com/AthenZ/athenz/blob/73b25572656f289cce501b4c2fe78f86656082e7/libs/go/athenzutils/principal.go
		// func ExtractServicePrincipal(x509Cert x509.Certificate) (string, error)
	}

	return &daemon{
		accessTokenCache: accessTokenCache,
		roleTokenCache:   roleTokenCache,

		ztsClient: ztsClient,
		saService: saService,

		tokenRESTAPI:        idConfig.TokenServerRESTAPI,
		tokenType:           tt,
		tokenDir:            idConfig.TokenDir,
		tokenRefresh:        idConfig.TokenRefresh,
		tokenExpiryInSecond: tokenExpiryInSecond,
		roleAuthHeader:      idConfig.RoleAuthHeader,

		useTokenServer: idConfig.UseTokenServer,
	}, nil
}

func (d *daemon) updateTokenCaches() <-chan error {
	var atErrorCount, rtErrorCount atomic.Int64
	atTargets := d.accessTokenCache.Keys()
	rtTargets := d.roleTokenCache.Keys()
	log.Infof("Attempting to fetch tokens from Athenz ZTS server: access token targets[%v], role token targets[%v]...", atTargets, rtTargets)
	echan := make(chan error, len(atTargets)+len(rtTargets))
	defer close(echan)
	wg := new(sync.WaitGroup)

	for _, t := range atTargets {
		wg.Add(1)
		go func(key CacheKey) {
			defer wg.Done()
			err := d.updateTokenWithRetry(key, mACCESS_TOKEN)
			echan <- err
			if err != nil {
				atErrorCount.Add(1)
			}
		}(t)
	}

	for _, t := range rtTargets {
		wg.Add(1)
		go func(key CacheKey) {
			defer wg.Done()
			err := d.updateTokenWithRetry(key, mROLE_TOKEN)
			echan <- err
			if err != nil {
				rtErrorCount.Add(1)
			}
		}(t)
	}

	wg.Wait()
	log.Infof("Token cache updated. accesstoken:success[%d],error[%d]; roletoken:success[%d],error[%d]", int64(len(atTargets))-atErrorCount.Load(), atErrorCount.Load(), int64(len(rtTargets))-rtErrorCount.Load(), rtErrorCount.Load())
	return echan
}

func (d *daemon) updateTokenWithRetry(key CacheKey, tt mode) error {
	// backoff config with first retry delay of 5s, and backoff retry until tokenRefresh / 4
	b := backoff.NewExponentialBackOff()
	b.InitialInterval = 5 * time.Second
	b.Multiplier = 2
	b.MaxElapsedTime = d.tokenRefresh / 4

	operation := func() error {
		return d.updateToken(key, tt)
	}
	notifyOnErr := func(err error, backoffDelay time.Duration) {
		log.Errorf("Failed to refresh tokens: %s. Retrying in %s", err.Error(), backoffDelay)
	}
	return backoff.RetryNotify(operation, b, notifyOnErr)
}

func (d *daemon) updateToken(key CacheKey, tt mode) error {
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

func (d *daemon) writeFilesWithRetry() error {
	// backoff config with first retry delay of 5s, and backoff retry until tokenRefresh / 4
	b := backoff.NewExponentialBackOff()
	b.InitialInterval = 5 * time.Second
	b.Multiplier = 2
	b.MaxElapsedTime = d.tokenRefresh / 4

	notifyOnErr := func(err error, backoffDelay time.Duration) {
		log.Errorf("Failed to write token files: %s. Retrying in %s", err.Error(), backoffDelay)
	}
	return backoff.RetryNotify(d.writeFiles, b, notifyOnErr)
}

func (d *daemon) writeFiles() error {
	if d.tokenDir == "" {
		log.Debugf("Skipping to write token files to directory[%s]", d.tokenDir)
		return nil
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

// Tokend starts the token server and refreshes tokens periodically.
func Tokend(idConfig *config.IdentityConfig, stopChan <-chan struct{}) (error, <-chan struct{}) {

	// validate
	if stopChan == nil {
		panic(fmt.Errorf("Tokend: stopChan cannot be empty"))
	}
	tt := newType(idConfig.TokenType)
	if idConfig.TokenServerAddr == "" || tt == 0 {
		log.Infof("Token server is disabled due to insufficient options: address[%s], roles[%s], token-type[%s]", idConfig.TokenServerAddr, idConfig.TargetDomainRoles, idConfig.TokenType)
		return nil, nil
	}

	d, err := newDaemon(idConfig, tt)
	if err != nil {
		return err, nil
	}

	// initialize preset tokens
	// mode=init, must output SOME preset tokens (allow SOME tokens to fail, and skip corresponding token files to output)
	// mode=refresh, on retry error, ignore and continue token server startup
	hasSuccess := false
	for err := range d.updateTokenCaches() {
		if err != nil {
			log.Errorf("Failed to fetch tokens after multiple retries: %s", err.Error())
		} else {
			hasSuccess = true
		}
	}
	if idConfig.Init && !hasSuccess {
		return fmt.Errorf("Unable to fetch ANY tokens for init mode"), nil
	}
	if err := d.writeFilesWithRetry(); err != nil {
		log.Errorf("Failed to write token files after multiple retries: %s", err.Error())
		if idConfig.Init {
			return fmt.Errorf("Unable to write token files for init mode: %w", err), nil
		}
	}

	// start token server daemon
	if idConfig.Init {
		log.Infof("Token server is disabled for init mode: address[%s]", idConfig.TokenServerAddr)
		return nil, nil
	}
	httpServer := &http.Server{
		Addr:      idConfig.TokenServerAddr,
		Handler:   newHandlerFunc(d, idConfig.TokenServerTimeout),
		TLSConfig: nil,
	}
	if idConfig.TokenServerTLSCertPath != "" && idConfig.TokenServerTLSKeyPath != "" {
		httpServer.TLSConfig, err = NewTLSConfig(idConfig.TokenServerTLSCAPath, idConfig.TokenServerTLSCertPath, idConfig.TokenServerTLSKeyPath)
		if err != nil {
			return err, nil
		}
	}
	serverDone := make(chan struct{}, 1)
	go func() {
		log.Infof("Starting token provider[%s]", idConfig.TokenServerAddr)
		listenAndServe := func() error {
			if httpServer.TLSConfig != nil {
				return httpServer.ListenAndServeTLS("", "")
			}
			return httpServer.ListenAndServe()
		}
		if err := listenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start token provider: %s", err.Error())
		}
		close(serverDone)
	}()

	// start token refresh daemon
	shutdownChan := make(chan struct{}, 1)
	t := time.NewTicker(d.tokenRefresh)
	go func() {
		defer t.Stop()
		defer close(shutdownChan)

		for {
			log.Infof("Will refresh tokens for after %s", d.tokenRefresh.String())
			select {
			case <-t.C:
				for err := range d.updateTokenCaches() {
					if err != nil {
						log.Errorf("Failed to refresh tokens after multiple retries: %s", err.Error())
					}
				}
				if err := d.writeFilesWithRetry(); err != nil {
					log.Errorf("Failed to write token files after multiple retries: %s", err.Error())
				}
			case <-stopChan:
				log.Info("Initiating shutdown of token provider daemon ...")
				time.Sleep(idConfig.ShutdownDelay)
				ctx, cancel := context.WithTimeout(context.Background(), idConfig.ShutdownTimeout)
				defer cancel()
				httpServer.SetKeepAlivesEnabled(false)
				if err := httpServer.Shutdown(ctx); err != nil {
					// graceful shutdown error should be fatal
					log.Fatalf("Failed to shutdown token provider: %s", err.Error())
				}
				<-serverDone
				return
			}
		}
	}()

	// start token cache report daemon (no need for graceful shutdown)
	report := func() {
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
		atcSize := d.accessTokenCache.Size()
		atcLen := d.accessTokenCache.Len()
		rtcSize := d.roleTokenCache.Size()
		rtcLen := d.roleTokenCache.Len()
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
	reportTicker := time.NewTicker(time.Minute)
	go func() {
		defer reportTicker.Stop()
		for {
			select {
			case <-reportTicker.C:
				report()
			case <-stopChan:
				// stop token cache report daemon
				return
			}
		}
	}()

	return nil, shutdownChan
}
