// Copyright 2026 LY Corporation
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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strconv"
	"sync"
	"time"

	"github.com/AthenZ/k8s-athenz-sia/v3/pkg/config"
	"github.com/AthenZ/k8s-athenz-sia/v3/third_party/log"
	"golang.org/x/sync/singleflight"
)

const (
	awsDefaultDuration = 900
	awsMaxDuration     = 43200
	awsMinimumTTL      = time.Minute
	awsRefreshInterval = 30 * time.Second
	awsMaxCacheEntries = 128
)

type awsCredentialKey struct {
	roleARN  string
	duration int
}

type awsCredentialProvider func(context.Context, awsCredentialKey) (AWSTemporaryCredentialsResponse, error)

// awsSigningHelper delegates AWS signing to the official helper, without a shell.
// Only file paths are passed; the helper reads the current service certificate on each refresh.
type awsSigningHelper struct {
	path, certificate, privateKey string
	settings                      config.AWSCredentialsConfig
}

func newAWSSigningHelper(idCfg *config.IdentityConfig) (*awsSigningHelper, error) {
	path, err := exec.LookPath("aws_signing_helper")
	if err != nil {
		return nil, fmt.Errorf("AWS credentials require aws_signing_helper on PATH: %w", err)
	}
	certs, keys := idCfg.ServiceCert.CopperArgos.Cert.Paths, idCfg.ServiceCert.CopperArgos.Key.Paths
	if len(certs) == 0 || len(keys) == 0 {
		return nil, errors.New("AWS credentials require service certificate and key paths")
	}
	return &awsSigningHelper{
		path: path, certificate: certs[0], privateKey: keys[0], settings: idCfg.AWSCredentials,
	}, nil
}

func (h *awsSigningHelper) credentials(ctx context.Context, key awsCredentialKey) (AWSTemporaryCredentialsResponse, error) {
	// #nosec G204 -- The executable is resolved from the operator's PATH; arguments use no shell and role/duration are validated by the endpoint.
	cmd := exec.CommandContext(ctx, h.path, "credential-process",
		"--certificate", h.certificate, "--private-key", h.privateKey,
		"--trust-anchor-arn", h.settings.TrustAnchorARN, "--profile-arn", h.settings.ProfileARN,
		"--role-arn", key.roleARN, "--region", h.settings.Region,
		"--session-duration", strconv.Itoa(key.duration))
	var output limitedAWSOutput
	cmd.Stdout = &output
	// Helper output, including diagnostics, may contain credential material.
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return AWSTemporaryCredentialsResponse{}, ctx.Err()
		}
		return AWSTemporaryCredentialsResponse{}, fmt.Errorf("aws_signing_helper failed: %w", err)
	}
	var response AWSTemporaryCredentialsResponse
	if err := json.Unmarshal(output.Bytes(), &response); err != nil {
		// JSON errors may quote the helper's output. Do not wrap them.
		return AWSTemporaryCredentialsResponse{}, errors.New("aws_signing_helper returned invalid credential JSON")
	}
	return response, nil
}

type limitedAWSOutput struct{ buffer bytes.Buffer }

func (b *limitedAWSOutput) Bytes() []byte { return b.buffer.Bytes() }

func (b *limitedAWSOutput) Write(p []byte) (int, error) {
	if b.buffer.Len()+len(p) > 64*1024 {
		return 0, errors.New("aws_signing_helper output exceeds 64 KiB")
	}
	return b.buffer.Write(p)
}

type awsCredentialEntry struct {
	credentials AWSTemporaryCredentialsResponse
	refreshAt   time.Time
	retryAfter  time.Time
	lastUsed    time.Time
}

// awsCredentialService mirrors the token caches' singleflight and background refresh,
// but schedules refreshes from AWS's actual expiration rather than TOKEN_REFRESH_INTERVAL.
type awsCredentialService struct {
	mu       sync.Mutex
	cache    map[awsCredentialKey]awsCredentialEntry
	group    singleflight.Group
	provider awsCredentialProvider
	now      func() time.Time
	ctx      context.Context
	cancel   context.CancelFunc
	timeout  time.Duration
	closed   bool
	fetches  sync.WaitGroup
}

func newAWSCredentialService(ctx context.Context, provider awsCredentialProvider, timeout time.Duration) *awsCredentialService {
	ctx, cancel := context.WithCancel(ctx)
	return &awsCredentialService{
		cache: make(map[awsCredentialKey]awsCredentialEntry), provider: provider,
		now: time.Now, ctx: ctx, cancel: cancel, timeout: timeout,
	}
}

func (s *awsCredentialService) get(ctx context.Context, key awsCredentialKey) (AWSTemporaryCredentialsResponse, error) {
	return s.load(ctx, key, true)
}

func (s *awsCredentialService) load(ctx context.Context, key awsCredentialKey, touch bool) (AWSTemporaryCredentialsResponse, error) {
	if err := ctx.Err(); err != nil {
		return AWSTemporaryCredentialsResponse{}, err
	}
	s.mu.Lock()
	entry, found := s.cache[key]
	if touch && found {
		entry.lastUsed = s.now()
		s.cache[key] = entry
	}
	closed := s.closed
	s.mu.Unlock()
	if closed || s.ctx.Err() != nil {
		return AWSTemporaryCredentialsResponse{}, context.Canceled
	}
	if found && s.now().Before(entry.refreshAt) && entry.credentials.Expiration.After(s.now().Add(awsMinimumTTL)) {
		return entry.credentials, nil
	}
	if found && s.now().Before(entry.retryAfter) {
		if entry.credentials.Expiration.After(s.now().Add(awsMinimumTTL)) {
			return entry.credentials, nil
		}
		return AWSTemporaryCredentialsResponse{}, errors.New("AWS credential refresh is backing off")
	}

	result := s.group.DoChan(key.roleARN+"|"+strconv.Itoa(key.duration), func() (interface{}, error) {
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return nil, context.Canceled
		}
		// Recheck after joining the flight: another fetch may have just completed.
		cached, ok := s.cache[key]
		if ok && (s.now().Before(cached.refreshAt) || s.now().Before(cached.retryAfter)) && cached.credentials.Expiration.After(s.now().Add(awsMinimumTTL)) {
			s.mu.Unlock()
			return cached.credentials, nil
		}
		if ok && s.now().Before(cached.retryAfter) {
			s.mu.Unlock()
			return nil, errors.New("AWS credential refresh is backing off")
		}
		s.fetches.Add(1)
		s.mu.Unlock()
		defer s.fetches.Done()

		// A caller cancelling its request does not cancel other callers sharing this fetch.
		fetchCtx, cancel := context.WithTimeout(s.ctx, s.timeout)
		defer cancel()
		credentials, err := s.provider(fetchCtx, key)
		if err != nil {
			s.mu.Lock()
			if current, exists := s.cache[key]; exists && !s.closed {
				current.retryAfter = s.now().Add(awsRefreshInterval)
				s.cache[key] = current
			}
			s.mu.Unlock()
			return nil, err
		}
		if err := fetchCtx.Err(); err != nil {
			return nil, err
		}
		now := s.now()
		if credentials.Version != 1 || credentials.AccessKeyId == "" || credentials.SecretAccessKey == "" || credentials.SessionToken == "" || !credentials.Expiration.After(now.Add(awsMinimumTTL)) {
			return nil, errors.New("AWS returned incomplete credentials or insufficient remaining lifetime")
		}
		// Refresh with 20% of the actual lifetime remaining, capped at five minutes.
		lead := credentials.Expiration.Sub(now) / 5
		if lead > 5*time.Minute {
			lead = 5 * time.Minute
		}
		if lead < awsMinimumTTL+awsRefreshInterval {
			lead = awsMinimumTTL + awsRefreshInterval
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.closed {
			return nil, context.Canceled
		}
		lastUsed := now
		if current, exists := s.cache[key]; exists {
			lastUsed = current.lastUsed
		} else if len(s.cache) >= awsMaxCacheEntries {
			// Bound memory even when callers request many roles or durations.
			var oldest awsCredentialKey
			var oldestTime time.Time
			for k, v := range s.cache {
				if oldestTime.IsZero() || v.lastUsed.Before(oldestTime) {
					oldest, oldestTime = k, v.lastUsed
				}
			}
			delete(s.cache, oldest)
		}
		s.cache[key] = awsCredentialEntry{credentials: credentials, refreshAt: credentials.Expiration.Add(-lead), lastUsed: lastUsed}
		return credentials, nil
	})
	select {
	case <-ctx.Done():
		return AWSTemporaryCredentialsResponse{}, ctx.Err()
	case <-s.ctx.Done():
		return AWSTemporaryCredentialsResponse{}, s.ctx.Err()
	case response := <-result:
		if response.Err != nil {
			// Keep serving a still-valid entry during an AWS outage, but never near/past expiry.
			if found && entry.credentials.Expiration.After(s.now().Add(awsMinimumTTL)) {
				log.Warnf("AWS credential refresh failed; retaining valid cache for role[%s]", key.roleARN)
				return entry.credentials, nil
			}
			return AWSTemporaryCredentialsResponse{}, response.Err
		}
		credentials := response.Val.(AWSTemporaryCredentialsResponse)
		if !credentials.Expiration.After(s.now().Add(awsMinimumTTL)) {
			return AWSTemporaryCredentialsResponse{}, errors.New("AWS credentials have insufficient remaining lifetime")
		}
		return credentials, nil
	}
}

func (s *awsCredentialService) refresh(ctx context.Context) {
	now := s.now()
	s.mu.Lock()
	keys := make([]awsCredentialKey, 0, len(s.cache))
	for key, entry := range s.cache {
		// Stop renewing entries that applications have not used for one requested session lifetime.
		if !now.Before(entry.lastUsed.Add(time.Duration(key.duration) * time.Second)) {
			delete(s.cache, key)
		} else if !now.Before(entry.refreshAt) {
			keys = append(keys, key)
		}
	}
	s.mu.Unlock()
	for _, key := range keys {
		if ctx.Err() != nil {
			return
		}
		if _, err := s.load(ctx, key, false); err != nil && ctx.Err() == nil {
			log.Warnf("Failed to refresh AWS credentials for role[%s]; retrying on the next refresh or request", key.roleARN)
		}
	}
}

func (s *awsCredentialService) run(ctx context.Context, shutdown <-chan struct{}) {
	ticker := time.NewTicker(awsRefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-shutdown:
			return
		case <-ticker.C:
			s.refresh(ctx)
		}
	}
}

func (s *awsCredentialService) close() {
	s.mu.Lock()
	s.closed = true
	s.cancel()
	s.mu.Unlock()
	s.fetches.Wait()
	s.mu.Lock()
	clear(s.cache)
	s.mu.Unlock()
}

func postAWSTemporaryCredentials(ts *tokenService, w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var request AWSTemporaryCredentialsRequestBody
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		http.Error(w, "invalid AWS credential request", http.StatusBadRequest)
		return
	}
	if err := decoder.Decode(new(interface{})); err != io.EOF {
		http.Error(w, "request must contain one JSON object", http.StatusBadRequest)
		return
	}
	duration := awsDefaultDuration
	if request.DurationSeconds != nil {
		duration = *request.DurationSeconds
	}
	if !ts.idCfg.AWSCredentials.ValidRoleARN(request.RoleArn) || duration < awsDefaultDuration || duration > awsMaxDuration {
		http.Error(w, "role_arn must be an IAM role ARN in the configured partition; duration_seconds must be 900..43200", http.StatusBadRequest)
		return
	}
	credentials, err := ts.awsCredentials.get(r.Context(), awsCredentialKey{roleARN: request.RoleArn, duration: duration})
	if r.Context().Err() != nil {
		return
	}
	if err != nil {
		// Return a fixed error. Neither helper output nor credential data belongs in diagnostics.
		log.Warnf("AWS credential request failed for role[%s]", request.RoleArn)
		http.Error(w, "unable to obtain AWS temporary credentials", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	// #nosec G117 -- Returning temporary credentials is this endpoint's purpose; they are never sent to logs.
	if err := json.NewEncoder(w).Encode(credentials); err != nil {
		log.Warn("Failed to write AWS credential response")
	}
}
