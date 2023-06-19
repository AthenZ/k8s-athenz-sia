// Copyright 2023 Yahoo Japan Corporation
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
	"strings"
	"time"

	"github.com/AthenZ/athenz/clients/go/zts"
	athenz "github.com/AthenZ/athenz/libs/go/sia/util"
	"github.com/cenkalti/backoff"
	"github.com/pkg/errors"

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

	tokenAPIEnable      bool
	tokenType           Type
	tokenDir            string
	tokenRefresh        time.Duration
	tokenExpiryInSecond int
	roleAuthHeader      string
}

func newDaemon(idConfig *config.IdentityConfig, tt Type) (*daemon, error) {

	// initialize token cache with placeholder
	tokenExpiryInSecond := int(idConfig.TokenExpiry.Seconds())
	accessTokenCache := NewLockedTokenCache()
	roleTokenCache := NewLockedTokenCache()
	targets := strings.Split(idConfig.TargetDomainRoles, ",")
	if len(targets) != 1 || idConfig.TargetDomainRoles != "" {
		if tt.Has(ACCESS_TOKEN) {
			for _, dr := range targets {
				domain, role, err := athenz.SplitRoleName(dr)
				if err != nil {
					return nil, fmt.Errorf("Invalid TargetDomainRoles[%s]: %s", idConfig.TargetDomainRoles, err.Error())
				}
				accessTokenCache.Store(CacheKey{Domain: domain, Role: role, MinExpiry: tokenExpiryInSecond}, &AccessToken{})
			}
		}
		if tt.Has(ROLE_TOKEN) {
			for _, dr := range targets {
				domain, role, err := athenz.SplitRoleName(dr)
				if err != nil {
					return nil, fmt.Errorf("Invalid TargetDomainRoles[%s]: %s", idConfig.TargetDomainRoles, err.Error())
				}
				roleTokenCache.Store(CacheKey{Domain: domain, Role: role, MinExpiry: tokenExpiryInSecond}, &RoleToken{})
			}
		}
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

		tokenAPIEnable:      idConfig.TokenServerAPIEnable,
		tokenType:           tt,
		tokenDir:            idConfig.TokenDir,
		tokenRefresh:        idConfig.TokenRefresh,
		tokenExpiryInSecond: tokenExpiryInSecond,
		roleAuthHeader:      idConfig.RoleAuthHeader,
	}, nil
}

func (d *daemon) updateTokenWithRetry() error {
	// backoff config with first retry delay of 5s, and backoff retry until tokenRefresh / 4
	b := backoff.NewExponentialBackOff()
	b.InitialInterval = 5 * time.Second
	b.Multiplier = 2
	b.MaxElapsedTime = d.tokenRefresh / 4

	notifyOnErr := func(err error, backoffDelay time.Duration) {
		log.Errorf("Failed to refresh tokens: %s. Retrying in %s", err.Error(), backoffDelay)
	}
	return backoff.RetryNotify(d.updateToken, b, notifyOnErr)
}

func (d *daemon) updateToken() error {
	if err := d.fetchTokensAndUpdateCaches(); err != nil {
		log.Warnf("Error while requesting tokens: %s", err.Error())
		return err
	}

	return d.writeFiles()
}

func (d *daemon) writeFiles() error {
	if d.tokenDir == "" {
		log.Debugf("Skipping to write token files to directory[%s]", d.tokenDir)
		return nil
	}

	w := util.NewWriter()
	d.accessTokenCache.Range(func(k CacheKey, t Token) error {
		domain := t.Domain()
		role := t.Role()
		at := t.Raw()
		log.Infof("[New Access Token] Domain: %s, Role: %s", domain, role)
		outPath := filepath.Join(d.tokenDir, domain+":role."+role+".accesstoken")
		log.Debugf("Saving Access Token[%d bytes] at %s", len(at), outPath)
		if err := w.AddBytes(outPath, 0644, []byte(at)); err != nil {
			return errors.Wrap(err, "unable to save access token")
		}
		return nil
	})
	d.roleTokenCache.Range(func(k CacheKey, t Token) error {
		domain := t.Domain()
		role := t.Role()
		rt := t.Raw()
		log.Infof("[New Role Token] Domain: %s, Role: %s", domain, role)
		outPath := filepath.Join(d.tokenDir, domain+":role."+role+".roletoken")
		log.Debugf("Saving Role Token[%d bytes] at %s", len(rt), outPath)
		if err := w.AddBytes(outPath, 0644, []byte(rt)); err != nil {
			return errors.Wrap(err, "unable to save role token")
		}
		return nil
	})

	return w.Save()
}

// fetchTokensAndUpdateCaches fetches tokens by ZTS API calls, and then updates caches as a batch
func (d *daemon) fetchTokensAndUpdateCaches() error {

	atTargets := d.accessTokenCache.Keys()
	rtTargets := d.roleTokenCache.Keys()
	log.Infof("Attempting to fetch tokens from Athenz ZTS server: access token targets[%v], role token targets[%v]...", atTargets, rtTargets)

	// fetch tokens
	atUpdateOps := make([]func(), 0, len(atTargets))
	for _, t := range atTargets {
		at, err := fetchAccessToken(d.ztsClient, t, d.saService)
		if err != nil {
			return err
		}
		atUpdateOps = append(atUpdateOps, func() {
			d.accessTokenCache.Store(t, at)
		})
	}
	rtUpdateOps := make([]func(), 0, len(rtTargets))
	for _, t := range rtTargets {
		rt, err := fetchRoleToken(d.ztsClient, t)
		if err != nil {
			return err
		}
		rtUpdateOps = append(rtUpdateOps, func() {
			d.roleTokenCache.Store(t, rt)
		})
	}
	log.Debugf("Successfully received tokens from Athenz ZTS server: accessTokens(%d), roleTokens(%d)", len(atUpdateOps), len(rtUpdateOps))
	for _, ops := range atUpdateOps {
		ops()
	}
	for _, ops := range rtUpdateOps {
		ops()
	}
	log.Infof("Successfully updated token cache: accessTokens(%d), roleTokens(%d)", len(atUpdateOps), len(rtUpdateOps))
	return nil
}

// Tokend starts the token server and refreshes tokens periodically.
func Tokend(idConfig *config.IdentityConfig, stopChan <-chan struct{}) (error, <-chan struct{}) {

	// validate
	if stopChan == nil {
		panic(fmt.Errorf("Tokend: stopChan cannot be empty"))
	}
	tt := newType(idConfig.TokenType)
	if idConfig.TokenServerAddr == "" || tt == 0 {
		log.Infof("Token server is disabled with empty options: address[%s], roles[%s], token-type[%s]", idConfig.TokenServerAddr, idConfig.TargetDomainRoles, idConfig.TokenType)
		return nil, nil
	}

	d, err := newDaemon(idConfig, tt)
	if err != nil {
		return err, nil
	}

	// initialize
	err = d.updateTokenWithRetry()
	if err != nil {
		log.Errorf("Failed to get initial tokens after multiple retries: %s", err.Error())
	}
	if idConfig.Init {
		log.Infof("Token server is disabled for init mode: address[%s]", idConfig.TokenServerAddr)
		return nil, nil
	}

	// start token server
	httpServer := &http.Server{
		Addr:    idConfig.TokenServerAddr,
		Handler: newHandlerFunc(d),
	}
	go func() {
		log.Infof("Starting token provider[%s]", idConfig.TokenServerAddr)
		if err := httpServer.ListenAndServe(); err != nil {
			log.Errorf("Failed to start token provider: %s", err.Error())
		}
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
				err := d.updateTokenWithRetry()
				if err != nil {
					log.Errorf("Failed to refresh tokens after multiple retries: %s", err.Error())
				}
			case <-stopChan:
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				httpServer.SetKeepAlivesEnabled(false)
				if err := httpServer.Shutdown(ctx); err != nil {
					log.Errorf("Failed to shutdown token provider: %s", err.Error())
				}
				return
			}
		}
	}()

	return nil, shutdownChan
}
