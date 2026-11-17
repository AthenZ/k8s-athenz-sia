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
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/AthenZ/k8s-athenz-sia/v3/pkg/config"
	"github.com/AthenZ/k8s-athenz-sia/v3/third_party/log"
	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	helper "github.com/aws/rolesanywhere-credential-helper/aws_signing_helper"
	"github.com/aws/rolesanywhere-credential-helper/rolesanywhere"
	"github.com/aws/smithy-go/middleware"
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

// awsSigningHelper uses AWS's Go signing package and CreateSession client directly.
// Each fetch takes the latest certificate/key snapshot from SIA's existing reloader.
type awsSigningHelper struct {
	certificate func() (*tls.Certificate, error)
	settings    config.AWSCredentialsConfig
	client      *rolesanywhere.Client
}

func newAWSSigningHelper(idCfg *config.IdentityConfig) (*awsSigningHelper, error) {
	certs, keys := idCfg.ServiceCert.CopperArgos.Cert.Paths, idCfg.ServiceCert.CopperArgos.Key.Paths
	if len(certs) == 0 || len(keys) == 0 {
		return nil, errors.New("AWS credentials require service certificate and key paths")
	}
	if idCfg.Reloader == nil {
		return nil, errors.New("AWS credentials require a service certificate reloader")
	}
	httpClient := awshttp.NewBuildableClient().WithTransportOptions(func(tr *http.Transport) {
		tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	})
	return &awsSigningHelper{
		certificate: idCfg.Reloader.GetLatestCertificate,
		settings:    idCfg.AWSCredentials,
		client: rolesanywhere.New(rolesanywhere.Options{
			Region: idCfg.AWSCredentials.Region, HTTPClient: awsCredentialHTTPClient{httpClient},
		}),
	}, nil
}

func (h *awsSigningHelper) credentials(ctx context.Context, key awsCredentialKey) (AWSTemporaryCredentialsResponse, error) {
	if err := ctx.Err(); err != nil {
		return AWSTemporaryCredentialsResponse{}, err
	}
	pair, err := h.certificate()
	if err != nil || pair == nil || len(pair.Certificate) == 0 {
		return AWSTemporaryCredentialsResponse{}, errors.New("AWS service certificate is unavailable")
	}
	certificate := pair.Leaf
	if certificate == nil {
		certificate, err = x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			return AWSTemporaryCredentialsResponse{}, errors.New("AWS service certificate is invalid")
		}
	}
	signer, ok := pair.PrivateKey.(crypto.Signer)
	if !ok {
		return AWSTemporaryCredentialsResponse{}, errors.New("AWS service private key cannot sign requests")
	}
	var algorithm string
	switch certificate.PublicKeyAlgorithm {
	case x509.RSA:
		algorithm = "AWS4-X509-RSA-SHA256"
	case x509.ECDSA:
		algorithm = "AWS4-X509-ECDSA-SHA256"
	default:
		return AWSTemporaryCredentialsResponse{}, errors.New("AWS service certificate requires an RSA or ECDSA key")
	}

	// GenerateCredentials uses context.TODO internally. Use its CreateSession client
	// and signing middleware so SIA's shared-fetch timeout and shutdown still cancel AWS requests.
	output, err := h.client.CreateSession(ctx, &rolesanywhere.CreateSessionInput{
		Cert:           aws.String(base64.StdEncoding.EncodeToString(certificate.Raw)),
		TrustAnchorArn: &h.settings.TrustAnchorARN, ProfileArn: &h.settings.ProfileARN,
		RoleArn: &key.roleARN, DurationSeconds: aws.Int32(int32(key.duration)),
	}, func(options *rolesanywhere.Options) {
		options.APIOptions = append(options.APIOptions, func(stack *middleware.Stack) error {
			// Replace access-key authentication with the official X.509 signer.
			for _, name := range []string{"Signing", "setLegacyContextSigningOptions", "GetIdentity"} {
				if _, err := stack.Finalize.Remove(name); err != nil {
					return err
				}
			}
			return stack.Finalize.Add(awsX509SigningMiddleware(signer, certificate, h.settings.Region, algorithm), middleware.After)
		})
	})
	if err != nil {
		if ctx.Err() != nil {
			return AWSTemporaryCredentialsResponse{}, ctx.Err()
		}
		// SDK errors may include response bodies; never expose them as diagnostics.
		return AWSTemporaryCredentialsResponse{}, errors.New("AWS CreateSession failed")
	}
	if len(output.CredentialSet) == 0 || output.CredentialSet[0].Credentials == nil {
		return AWSTemporaryCredentialsResponse{}, errors.New("AWS returned no credentials")
	}
	credentials := output.CredentialSet[0].Credentials
	expiration, err := time.Parse(time.RFC3339, aws.ToString(credentials.Expiration))
	if err != nil {
		return AWSTemporaryCredentialsResponse{}, errors.New("AWS returned invalid credential expiration")
	}
	return AWSTemporaryCredentialsResponse{
		Version: N1, AccessKeyId: aws.ToString(credentials.AccessKeyId),
		SecretAccessKey: aws.ToString(credentials.SecretAccessKey),
		SessionToken:    aws.ToString(credentials.SessionToken), Expiration: expiration,
	}, nil
}

// awsX509Signer adapts crypto.Signer to the helper's unhashed message input.
// The helper exits the process when Sign returns an error, so defer that error to
// our middleware, which rejects the request before the HTTP client is called.
type awsX509Signer struct {
	crypto.Signer
	err error
}

func (s *awsX509Signer) Sign(random io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	digest := sha256.Sum256(message)
	signature, err := s.Signer.Sign(random, digest[:], opts)
	s.err = err
	return signature, nil
}

func awsX509SigningMiddleware(signer crypto.Signer, certificate *x509.Certificate, region, algorithm string) middleware.FinalizeMiddleware {
	return middleware.FinalizeMiddlewareFunc("Signing", func(ctx context.Context, in middleware.FinalizeInput, next middleware.FinalizeHandler) (middleware.FinalizeOutput, middleware.Metadata, error) {
		safeSigner := &awsX509Signer{Signer: signer}
		sign := helper.CreateRequestSignFinalizeFunction(safeSigner, region, algorithm, certificate, nil)
		return sign(ctx, in, middleware.FinalizeHandlerFunc(func(ctx context.Context, in middleware.FinalizeInput) (middleware.FinalizeOutput, middleware.Metadata, error) {
			if safeSigner.err != nil {
				return middleware.FinalizeOutput{}, middleware.Metadata{}, errors.New("AWS request signing failed")
			}
			return next.HandleFinalize(ctx, in)
		}))
	})
}

type awsCredentialHTTPClient struct{ aws.HTTPClient }

func (c awsCredentialHTTPClient) Do(request *http.Request) (*http.Response, error) {
	response, err := c.HTTPClient.Do(request)
	if err == nil && response != nil && response.Body != nil {
		response.Body = http.MaxBytesReader(nil, response.Body, 64*1024)
	}
	return response, err
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
	mu         sync.Mutex
	cache      map[awsCredentialKey]awsCredentialEntry
	group      singleflight.Group
	provider   awsCredentialProvider
	now        func() time.Time
	done       chan struct{}
	stopParent func() bool
	inflight   map[awsCredentialKey]context.CancelFunc
	timeout    time.Duration
	closed     bool
	fetches    sync.WaitGroup
}

func newAWSCredentialService(ctx context.Context, provider awsCredentialProvider, timeout time.Duration) *awsCredentialService {
	s := &awsCredentialService{
		cache: make(map[awsCredentialKey]awsCredentialEntry), provider: provider,
		now: time.Now, done: make(chan struct{}), timeout: timeout,
		inflight: make(map[awsCredentialKey]context.CancelFunc),
	}
	// Publish the callback while locked: an already-cancelled parent may run it immediately.
	s.mu.Lock()
	s.stopParent = context.AfterFunc(ctx, s.close)
	s.mu.Unlock()
	if ctx.Err() != nil {
		s.close()
	}
	return s
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
	if closed {
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
		// Preserve request values, but give shared work its own timeout and service lifetime.
		// Cancelling one caller must not cancel the fetch for the other waiters.
		fetchCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.timeout)
		s.inflight[key] = cancel
		s.fetches.Add(1)
		s.mu.Unlock()
		defer func() {
			cancel()
			s.mu.Lock()
			delete(s.inflight, key)
			s.mu.Unlock()
			s.fetches.Done()
		}()
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
	case <-s.done:
		return AWSTemporaryCredentialsResponse{}, context.Canceled
	case response := <-result:
		if err := ctx.Err(); err != nil {
			return AWSTemporaryCredentialsResponse{}, err
		}
		select {
		case <-s.done:
			return AWSTemporaryCredentialsResponse{}, context.Canceled
		default:
		}
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
	if !s.closed {
		s.closed = true
		close(s.done)
		s.stopParent()
		for _, cancel := range s.inflight {
			cancel()
		}
	}
	s.mu.Unlock()
	s.fetches.Wait()
	s.mu.Lock()
	clear(s.cache)
	s.mu.Unlock()
}

func parseAWSTemporaryCredentialsRequest(w http.ResponseWriter, r *http.Request) (AWSTemporaryCredentialsRequestBody, error) {
	var request AWSTemporaryCredentialsRequestBody
	if r.Method == http.MethodGet {
		query, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil {
			return request, errors.New("invalid AWS credential query")
		}
		for name, values := range query {
			if len(values) != 1 {
				return request, errors.New("query parameters must not be repeated")
			}
			switch name {
			case "role_arn":
				request.RoleArn = values[0]
			case "duration_seconds":
				duration, err := strconv.Atoi(values[0])
				if err != nil {
					return request, errors.New("duration_seconds must be an integer")
				}
				request.DurationSeconds = &duration
			default:
				return request, errors.New("unknown AWS credential query parameter")
			}
		}
		return request, nil
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return request, errors.New("invalid AWS credential request")
	}
	if err := decoder.Decode(new(interface{})); err != io.EOF {
		return request, errors.New("request must contain one JSON object")
	}
	return request, nil
}

func serveAWSTemporaryCredentials(ts *tokenService, w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	request, err := parseAWSTemporaryCredentialsRequest(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
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
		// Return a fixed error. Neither AWS response bodies nor credential data belongs in diagnostics.
		log.Warnf("AWS credential request failed for role[%s]", request.RoleArn)
		http.Error(w, "unable to obtain AWS temporary credentials", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	var response interface{} = credentials
	if r.Method == http.MethodGet {
		// The container credential provider uses Token; credential_process uses SessionToken.
		response = AWSContainerCredentialsResponse{
			AccessKeyId: credentials.AccessKeyId, SecretAccessKey: credentials.SecretAccessKey,
			Token: credentials.SessionToken, Expiration: credentials.Expiration,
		}
	}
	// #nosec G117 -- Returning temporary credentials is this endpoint's purpose; they are never sent to logs.
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Warn("Failed to write AWS credential response")
	}
}
