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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AthenZ/k8s-athenz-sia/v3/pkg/config"
	"github.com/AthenZ/k8s-athenz-sia/v3/third_party/log"
	"github.com/prometheus/client_golang/prometheus"
)

const testAWSRole = "arn:aws:iam::123456789012:role/reader"

var awsTestLoggerOnce sync.Once

// All responses are deliberately synthetic. Tests never load a certificate/key or call AWS.
func syntheticAWSCredentials(now time.Time) AWSTemporaryCredentialsResponse {
	return AWSTemporaryCredentialsResponse{
		Version: 1, AccessKeyId: "test-access-key", SecretAccessKey: "test-secret-key",
		SessionToken: "test-session", Expiration: now.Add(15 * time.Minute),
	}
}

func testAWSCredentialCache(t *testing.T, provider awsCredentialProvider) *awsCredentialService {
	t.Helper()
	awsTestLoggerOnce.Do(func() { log.InitLogger("", "ERROR", true) })
	s := newAWSCredentialService(context.Background(), provider, time.Second)
	t.Cleanup(s.close)
	return s
}

func TestAWSCredentialCacheReuseAndKeyIsolation(t *testing.T) {
	var calls atomic.Int32
	s := testAWSCredentialCache(t, func(_ context.Context, _ awsCredentialKey) (AWSTemporaryCredentialsResponse, error) {
		calls.Add(1)
		return syntheticAWSCredentials(time.Now()), nil
	})
	for _, key := range []awsCredentialKey{
		{testAWSRole, 900}, {testAWSRole, 900}, {testAWSRole, 3600}, {testAWSRole + "-other", 900},
	} {
		if _, err := s.get(context.Background(), key); err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 3 {
		t.Fatalf("provider calls = %d, want 3", calls.Load())
	}
}

func TestAWSCredentialConcurrentRequestsShareFetch(t *testing.T) {
	var calls atomic.Int32
	release := make(chan struct{})
	s := testAWSCredentialCache(t, func(ctx context.Context, _ awsCredentialKey) (AWSTemporaryCredentialsResponse, error) {
		calls.Add(1)
		select {
		case <-release:
			return syntheticAWSCredentials(time.Now()), nil
		case <-ctx.Done():
			return AWSTemporaryCredentialsResponse{}, ctx.Err()
		}
	})
	var wg sync.WaitGroup
	errs := make(chan error, 32)
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.get(context.Background(), awsCredentialKey{testAWSRole, 900})
			errs <- err
		}()
	}
	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("provider calls = %d, want 1", calls.Load())
	}
}

func TestAWSCredentialCancellationDoesNotCancelSharedFetch(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	s := testAWSCredentialCache(t, func(ctx context.Context, _ awsCredentialKey) (AWSTemporaryCredentialsResponse, error) {
		if calls.Add(1) == 1 {
			close(started)
		}
		select {
		case <-release:
			return syntheticAWSCredentials(time.Now()), nil
		case <-ctx.Done():
			return AWSTemporaryCredentialsResponse{}, ctx.Err()
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		_, err := s.get(ctx, awsCredentialKey{testAWSRole, 900})
		errCh <- err
	}()
	<-started
	cancel()
	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled request error = %v", err)
	}
	close(release)
	if _, err := s.get(context.Background(), awsCredentialKey{testAWSRole, 900}); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatal("cancelling the first caller caused an additional fetch")
	}
}

func TestAWSCredentialFetchPreservesRequestContextValues(t *testing.T) {
	const requestID = "synthetic-request-id"
	s := testAWSCredentialCache(t, func(ctx context.Context, _ awsCredentialKey) (AWSTemporaryCredentialsResponse, error) {
		if ctx.Value(contextKeyRequestID) != requestID {
			return AWSTemporaryCredentialsResponse{}, errors.New("request metadata was lost")
		}
		return syntheticAWSCredentials(time.Now()), nil
	})
	ctx := context.WithValue(context.Background(), contextKeyRequestID, requestID)
	if _, err := s.get(ctx, awsCredentialKey{testAWSRole, 900}); err != nil {
		t.Fatal(err)
	}
}

func TestAWSCredentialParentCancellationStopsSharedFetch(t *testing.T) {
	parent, cancelParent := context.WithCancel(context.Background())
	defer cancelParent()
	started, stopped := make(chan struct{}), make(chan struct{})
	s := newAWSCredentialService(parent, func(ctx context.Context, _ awsCredentialKey) (AWSTemporaryCredentialsResponse, error) {
		close(started)
		<-ctx.Done()
		close(stopped)
		return AWSTemporaryCredentialsResponse{}, ctx.Err()
	}, time.Second)
	t.Cleanup(s.close)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := s.get(ctx, awsCredentialKey{testAWSRole, 900})
		result <- err
	}()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("shared fetch did not start")
	}
	cancelParent()
	select {
	case <-stopped:
	case <-ctx.Done():
		t.Fatal("parent cancellation did not stop the provider")
	}
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("parent cancellation error = %v", err)
	}
	if _, err := s.get(ctx, awsCredentialKey{testAWSRole, 900}); !errors.Is(err, context.Canceled) {
		t.Fatalf("closed service error = %v", err)
	}
}

func TestAWSCredentialAlreadyCancelledParent(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	cancel()
	var calls atomic.Int32
	s := newAWSCredentialService(parent, func(_ context.Context, _ awsCredentialKey) (AWSTemporaryCredentialsResponse, error) {
		calls.Add(1)
		return syntheticAWSCredentials(time.Now()), nil
	}, time.Second)
	t.Cleanup(s.close)
	if _, err := s.get(context.Background(), awsCredentialKey{testAWSRole, 900}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled parent error = %v", err)
	}
	if calls.Load() != 0 {
		t.Fatal("a cancelled service invoked the provider")
	}
}

func TestAWSCredentialRefreshFailureAndExpiry(t *testing.T) {
	now := time.Unix(1800000000, 0)
	var fail atomic.Bool
	var calls atomic.Int32
	s := testAWSCredentialCache(t, func(_ context.Context, _ awsCredentialKey) (AWSTemporaryCredentialsResponse, error) {
		calls.Add(1)
		if fail.Load() {
			return AWSTemporaryCredentialsResponse{}, errors.New("synthetic failure")
		}
		return syntheticAWSCredentials(now), nil
	})
	s.now = func() time.Time { return now }
	key := awsCredentialKey{testAWSRole, 900}
	if _, err := s.get(context.Background(), key); err != nil {
		t.Fatal(err)
	}
	fail.Store(true)
	now = now.Add(12 * time.Minute)
	if _, err := s.get(context.Background(), key); err != nil {
		t.Fatalf("valid cached credentials should survive refresh failure: %v", err)
	}
	for range 10 {
		if _, err := s.get(context.Background(), key); err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 2 {
		t.Fatal("requests retried AWS during the refresh failure cooldown")
	}
	now = now.Add(2 * time.Minute)
	if _, err := s.get(context.Background(), key); err == nil {
		t.Fatal("credentials with only a minute remaining were returned")
	}
	now = now.Add(2 * time.Minute)
	if _, err := s.get(context.Background(), key); err == nil {
		t.Fatal("expired credentials were returned")
	}
}

func TestAWSCredentialBackgroundRefreshAndIdleEviction(t *testing.T) {
	now := time.Unix(1800000000, 0)
	var calls atomic.Int32
	s := testAWSCredentialCache(t, func(_ context.Context, _ awsCredentialKey) (AWSTemporaryCredentialsResponse, error) {
		calls.Add(1)
		return syntheticAWSCredentials(now), nil
	})
	s.now = func() time.Time { return now }
	key := awsCredentialKey{testAWSRole, 900}
	if _, err := s.get(context.Background(), key); err != nil {
		t.Fatal(err)
	}
	now = now.Add(11 * time.Minute)
	s.refresh(context.Background())
	if calls.Load() != 1 {
		t.Fatal("cache refreshed before its refresh time")
	}
	now = now.Add(time.Minute)
	s.refresh(context.Background())
	if calls.Load() != 2 {
		t.Fatal("cache was not refreshed before expiration")
	}
	now = now.Add(3 * time.Minute)
	s.refresh(context.Background())
	if len(s.cache) != 0 || calls.Load() != 2 {
		t.Fatal("background refresh kept an unused entry alive")
	}
}

func TestAWSCredentialInvalidResponsesAreNotCached(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*AWSTemporaryCredentialsResponse)
	}{
		{"missing access key", func(c *AWSTemporaryCredentialsResponse) { c.AccessKeyId = "" }},
		{"missing secret key", func(c *AWSTemporaryCredentialsResponse) { c.SecretAccessKey = "" }},
		{"missing session", func(c *AWSTemporaryCredentialsResponse) { c.SessionToken = "" }},
		{"wrong version", func(c *AWSTemporaryCredentialsResponse) { c.Version = 2 }},
		{"expired", func(c *AWSTemporaryCredentialsResponse) { c.Expiration = time.Now().Add(-time.Minute) }},
		{"near expiry", func(c *AWSTemporaryCredentialsResponse) { c.Expiration = time.Now().Add(30 * time.Second) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := testAWSCredentialCache(t, func(_ context.Context, _ awsCredentialKey) (AWSTemporaryCredentialsResponse, error) {
				c := syntheticAWSCredentials(time.Now())
				tc.change(&c)
				return c, nil
			})
			if _, err := s.get(context.Background(), awsCredentialKey{testAWSRole, 900}); err == nil {
				t.Fatal("invalid provider response accepted")
			}
			if len(s.cache) != 0 {
				t.Fatal("invalid provider response cached")
			}
		})
	}
}

func TestAWSCredentialCacheIsBounded(t *testing.T) {
	s := testAWSCredentialCache(t, func(_ context.Context, _ awsCredentialKey) (AWSTemporaryCredentialsResponse, error) {
		return syntheticAWSCredentials(time.Now()), nil
	})
	for i := range awsMaxCacheEntries + 5 {
		if _, err := s.get(context.Background(), awsCredentialKey{fmt.Sprintf("%s-%d", testAWSRole, i), 900}); err != nil {
			t.Fatal(err)
		}
	}
	if len(s.cache) != awsMaxCacheEntries {
		t.Fatalf("cache entries = %d, want %d", len(s.cache), awsMaxCacheEntries)
	}
}

func TestAWSCredentialTimeoutAndShutdown(t *testing.T) {
	started := make(chan struct{}, 1)
	s := testAWSCredentialCache(t, func(ctx context.Context, _ awsCredentialKey) (AWSTemporaryCredentialsResponse, error) {
		started <- struct{}{}
		<-ctx.Done()
		return AWSTemporaryCredentialsResponse{}, ctx.Err()
	})
	s.timeout = 20 * time.Millisecond
	if _, err := s.get(context.Background(), awsCredentialKey{testAWSRole, 900}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("fetch timeout error = %v", err)
	}
	<-started
	s.timeout = time.Second
	errCh := make(chan error, 1)
	go func() {
		_, err := s.get(context.Background(), awsCredentialKey{testAWSRole, 900})
		errCh <- err
	}()
	<-started
	s.close()
	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("shutdown error = %v", err)
	}
	if len(s.cache) != 0 {
		t.Fatal("shutdown did not clear the cache")
	}
}

func TestAWSTemporaryCredentialsEndpoint(t *testing.T) {
	roleQuery := "role_arn=" + url.QueryEscape(testAWSRole)
	specialRole := "arn:aws:iam::123456789012:role/team+one/reader+writer"
	for _, tc := range []struct {
		name, method, query, body string
		status                    int
		disabled, noREST          bool
		fail                      bool
		wantDuration              int
		wantRole                  string
	}{
		{name: "default duration", method: "POST", body: `{"role_arn":"` + testAWSRole + `"}`, status: 200, wantDuration: 900},
		{name: "longer session", method: "POST", body: `{"role_arn":"` + testAWSRole + `","duration_seconds":43200}`, status: 200, wantDuration: 43200},
		{name: "GET default duration", method: "GET", query: roleQuery, status: 200, wantDuration: 900},
		{name: "GET longer session", method: "GET", query: roleQuery + "&duration_seconds=43200", status: 200, wantDuration: 43200},
		{name: "GET escaped role", method: "GET", query: "role_arn=" + url.QueryEscape(specialRole), status: 200, wantDuration: 900, wantRole: specialRole},
		{name: "GET missing role", method: "GET", status: 400},
		{name: "GET empty role", method: "GET", query: "role_arn=", status: 400},
		{name: "GET invalid ARN", method: "GET", query: "role_arn=--debug", status: 400},
		{name: "GET malformed escape", method: "GET", query: roleQuery + "&duration_seconds=%zz", status: 400},
		{name: "GET malformed separator", method: "GET", query: roleQuery + ";duration_seconds=900", status: 400},
		{name: "GET repeated role", method: "GET", query: roleQuery + "&" + roleQuery, status: 400},
		{name: "GET repeated duration", method: "GET", query: roleQuery + "&duration_seconds=900&duration_seconds=3600", status: 400},
		{name: "GET unknown field", method: "GET", query: roleQuery + "&profile_arn=caller-supplied", status: 400},
		{name: "GET invalid duration", method: "GET", query: roleQuery + "&duration_seconds=abc", status: 400},
		{name: "GET empty duration", method: "GET", query: roleQuery + "&duration_seconds=", status: 400},
		{name: "GET fractional duration", method: "GET", query: roleQuery + "&duration_seconds=900.5", status: 400},
		{name: "GET overflowing duration", method: "GET", query: roleQuery + "&duration_seconds=999999999999999999999", status: 400},
		{name: "GET too short", method: "GET", query: roleQuery + "&duration_seconds=899", status: 400},
		{name: "GET too long", method: "GET", query: roleQuery + "&duration_seconds=43201", status: 400},
		{name: "GET provider failure", method: "GET", query: roleQuery, fail: true, status: 503},
		{name: "GET disabled", method: "GET", query: roleQuery, disabled: true, status: 404},
		{name: "GET REST disabled", method: "GET", query: roleQuery, noREST: true, status: 404},
		{name: "wrong method", method: "PUT", status: 405},
		{name: "missing role", method: "POST", body: `{}`, status: 400},
		{name: "bad JSON", method: "POST", body: `{`, status: 400},
		{name: "unknown field", method: "POST", body: `{"role_arn":"` + testAWSRole + `","profile_arn":"caller-supplied"}`, status: 400},
		{name: "two objects", method: "POST", body: `{"role_arn":"` + testAWSRole + `"} {}`, status: 400},
		{name: "too short", method: "POST", body: `{"role_arn":"` + testAWSRole + `","duration_seconds":899}`, status: 400},
		{name: "too long", method: "POST", body: `{"role_arn":"` + testAWSRole + `","duration_seconds":43201}`, status: 400},
		{name: "invalid ARN", method: "POST", body: `{"role_arn":"--debug"}`, status: 400},
		{name: "oversized", method: "POST", body: strings.Repeat(" ", 4097), status: 400},
		{name: "provider failure", method: "POST", body: `{"role_arn":"` + testAWSRole + `"}`, fail: true, status: 503},
		{name: "disabled", method: "POST", body: `{}`, disabled: true, status: 404},
		{name: "REST disabled", method: "POST", body: `{}`, noREST: true, status: 404},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			s := testAWSCredentialCache(t, func(_ context.Context, key awsCredentialKey) (AWSTemporaryCredentialsResponse, error) {
				calls.Add(1)
				if tc.fail {
					return AWSTemporaryCredentialsResponse{}, errors.New("synthetic-sensitive-diagnostic")
				}
				wantRole := testAWSRole
				if tc.wantRole != "" {
					wantRole = tc.wantRole
				}
				if key.roleARN != wantRole || key.duration != tc.wantDuration {
					return AWSTemporaryCredentialsResponse{}, errors.New("wrong role or duration")
				}
				return syntheticAWSCredentials(time.Now()), nil
			})
			cfg := &config.IdentityConfig{
				AWSCredentials: config.AWSCredentialsConfig{TrustAnchorARN: "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/test"},
				TokenServer:    config.DerivedTokenServer{RestAPI: config.RestAPIMode{Use: !tc.noREST}},
			}
			ts := &tokenService{idCfg: cfg, awsCredentials: s}
			if tc.disabled {
				ts.awsCredentials = nil
			}
			w := httptest.NewRecorder()
			target := "/awstempcred"
			if tc.query != "" {
				target += "?" + tc.query
			}
			newHandlerFunc(ts, time.Second).ServeHTTP(w, httptest.NewRequest(tc.method, target, strings.NewReader(tc.body)))
			if w.Code != tc.status {
				t.Fatalf("status = %d, want %d", w.Code, tc.status)
			}
			if tc.status == 200 {
				var response map[string]interface{}
				if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
					t.Fatal("invalid response JSON")
				}
				fields := []string{"AccessKeyId", "SecretAccessKey", "Expiration"}
				tokenField := "SessionToken"
				if tc.method == "GET" {
					tokenField = "Token"
					if _, ok := response["SessionToken"]; ok {
						t.Error("container response should use Token for the session token")
					}
				} else {
					fields = append(fields, "Version")
				}
				for _, field := range append(fields, tokenField) {
					if _, ok := response[field]; !ok {
						t.Errorf("credential field %s missing", field)
					}
				}
				if response[tokenField] != "test-session" {
					t.Error("session token was not mapped to the expected response field")
				}
				if w.Header().Get("Cache-Control") != "no-store" {
					t.Fatal("credential response missing no-store")
				}
			} else if w.Body.String() == "" || strings.Contains(w.Body.String(), "synthetic-sensitive-diagnostic") {
				t.Fatal("missing error body or leaked provider diagnostics")
			}
			if tc.status == 405 && w.Header().Get("Allow") != "GET, POST" {
				t.Fatal("method error missing Allow header")
			}
			if tc.status != 200 && !tc.fail && calls.Load() != 0 {
				t.Fatal("invalid or disabled request reached the provider")
			}
		})
	}
}

func TestAWSTemporaryCredentialsMethodsShareCache(t *testing.T) {
	var calls atomic.Int32
	s := testAWSCredentialCache(t, func(_ context.Context, _ awsCredentialKey) (AWSTemporaryCredentialsResponse, error) {
		calls.Add(1)
		return syntheticAWSCredentials(time.Now()), nil
	})
	cfg := &config.IdentityConfig{
		AWSCredentials: config.AWSCredentialsConfig{TrustAnchorARN: "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/test"},
		TokenServer:    config.DerivedTokenServer{RestAPI: config.RestAPIMode{Use: true}},
	}
	handler := newHandlerFunc(&tokenService{idCfg: cfg, awsCredentials: s}, time.Second)
	requests := []*http.Request{
		httptest.NewRequest("POST", "/awstempcred", strings.NewReader(`{"role_arn":"`+testAWSRole+`"}`)),
		httptest.NewRequest("GET", "/awstempcred?role_arn="+url.QueryEscape(testAWSRole)+"&duration_seconds=900", nil),
	}
	for _, request := range requests {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, request)
		if w.Code != 200 {
			t.Fatalf("%s status = %d, want 200", request.Method, w.Code)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("provider calls = %d, want GET and POST to share one fetch", calls.Load())
	}
}

func TestAWSSigningHelper(t *testing.T) {
	for _, tc := range []struct {
		name, script string
		wantErr      bool
	}{
		{"success", `printf '%s\n' '{"Version":1,"AccessKeyId":"test-access-key","SecretAccessKey":"test-secret-key","SessionToken":"test-session","Expiration":"2100-01-01T00:00:00Z"}'`, false},
		{"invalid JSON", `printf '%s\n' 'synthetic-sensitive-diagnostic'`, true},
		{"invalid type", `printf '%s\n' '{"Version":"synthetic-sensitive-diagnostic"}'`, true},
		{"failure", `printf '%s\n' 'synthetic-sensitive-diagnostic' >&2; exit 7`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path, argsPath := filepath.Join(dir, "fake-helper"), filepath.Join(dir, "arguments")
			t.Setenv("AWS_TEST_ARGS_FILE", argsPath)
			script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$AWS_TEST_ARGS_FILE\"\n" + tc.script + "\n"
			// #nosec G306 -- This synthetic test helper must be executable by its owner.
			if err := os.WriteFile(path, []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			helper := awsSigningHelper{path: path, certificate: "/synthetic/cert.pem", privateKey: "/synthetic/key.pem", settings: config.AWSCredentialsConfig{
				TrustAnchorARN: "test-anchor", ProfileARN: "test-profile", Region: "us-east-1",
			}}
			_, err := helper.credentials(context.Background(), awsCredentialKey{testAWSRole, 3600})
			if (err != nil) != tc.wantErr {
				t.Fatalf("error = %v, want error %v", err, tc.wantErr)
			}
			if err != nil && strings.Contains(err.Error(), "synthetic-sensitive-diagnostic") {
				t.Fatal("helper output leaked into the error")
			}
			// #nosec G304 -- The path is a fixed filename within t.TempDir; the file contains only command arguments.
			args, err := os.ReadFile(argsPath)
			if err != nil {
				t.Fatal(err)
			}
			want := strings.Join([]string{"credential-process", "--certificate", "/synthetic/cert.pem", "--private-key", "/synthetic/key.pem", "--trust-anchor-arn", "test-anchor", "--profile-arn", "test-profile", "--role-arn", testAWSRole, "--region", "us-east-1", "--session-duration", "3600", ""}, "\n")
			if string(args) != want {
				t.Fatal("helper command arguments differ")
			}
		})
	}
}

func TestAWSSigningHelperOutputLimitAndCancellation(t *testing.T) {
	var output limitedAWSOutput
	if _, err := output.Write(make([]byte, 64*1024+1)); err == nil {
		t.Fatal("oversized helper output accepted")
	}
	path := filepath.Join(t.TempDir(), "fake-helper")
	// #nosec G306 -- This synthetic test helper must be executable by its owner.
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexec sleep 30\n"), 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	helper := awsSigningHelper{path: path}
	if _, err := helper.credentials(ctx, awsCredentialKey{testAWSRole, 900}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("helper cancellation error = %v", err)
	}
}

func TestAWSOnlyServiceInitialization(t *testing.T) {
	awsTestLoggerOnce.Do(func() { log.InitLogger("", "ERROR", true) })
	dir := t.TempDir()
	t.Setenv("PATH", dir)
	cfg := &config.IdentityConfig{
		TokenType:      "",
		AWSCredentials: config.AWSCredentialsConfig{Use: true},
		TokenServer: config.DerivedTokenServer{
			Use: true, Addr: "127.0.0.1:0", ServerTimeout: time.Second,
			RestAPI: config.RestAPIMode{Use: true},
		},
		ServiceCert: config.DerivedServiceCert{CopperArgos: config.CopperArgosMode{
			Cert: config.X509File{Paths: []string{"/synthetic/cert.pem"}},
			Key:  config.X509File{Paths: []string{"/synthetic/key.pem"}},
		}},
	}
	if _, err := New(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "aws_signing_helper") {
		t.Fatal("missing helper did not fail startup")
	}
	// #nosec G306 -- LookPath requires an executable; this helper is never invoked.
	if err := os.WriteFile(filepath.Join(dir, "aws_signing_helper"), []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	daemon, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	ts := daemon.(*tokenService)
	t.Cleanup(ts.Shutdown)
	t.Cleanup(func() {
		prometheus.Unregister(ts.accessTokenCache.(*LockedTokenCache))
		prometheus.Unregister(ts.roleTokenCache.(*LockedTokenCache))
	})
	if ts.awsCredentials == nil || ts.tokenServer == nil || ts.ztsClient != nil {
		t.Fatal("AWS-only startup did not wire the endpoint without a ZTS client")
	}
}
