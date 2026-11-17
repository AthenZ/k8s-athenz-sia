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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/AthenZ/k8s-athenz-sia/v3/pkg/config"
	"github.com/aws/rolesanywhere-credential-helper/rolesanywhere"
)

const awsTestSessionResponse = `{"credentialSet":[{"credentials":{"accessKeyId":"test-access-key","secretAccessKey":"test-secret-key","sessionToken":"test-session","expiration":"2100-01-01T00:00:00Z"}}]}`

type awsTestHTTPClient func(*http.Request) (*http.Response, error)

func (f awsTestHTTPClient) Do(request *http.Request) (*http.Response, error) { return f(request) }

type awsTestSigner struct{ err error }

func (s awsTestSigner) Public() crypto.PublicKey { return nil }

func (s awsTestSigner) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	return []byte("synthetic-signature"), s.err
}

func awsTestCertificate(raw string, algorithm x509.PublicKeyAlgorithm) *tls.Certificate {
	return &tls.Certificate{
		Certificate: [][]byte{[]byte(raw)}, PrivateKey: awsTestSigner{},
		Leaf: &x509.Certificate{Raw: []byte(raw), SerialNumber: big.NewInt(1), PublicKeyAlgorithm: algorithm},
	}
}

func awsTestResponse(request *http.Request, status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status, Header: http.Header{"Content-Type": []string{"application/json"}},
		Body: io.NopCloser(strings.NewReader(body)), Request: request,
	}
}

func awsTestSigningHelper(client awsTestHTTPClient) *awsSigningHelper {
	return &awsSigningHelper{
		certificate: func() (*tls.Certificate, error) { return awsTestCertificate("synthetic-certificate", x509.RSA), nil },
		settings: config.AWSCredentialsConfig{
			TrustAnchorARN: "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/test",
			ProfileARN:     "arn:aws:rolesanywhere:us-east-1:123456789012:profile/test", Region: "us-east-1",
		},
		client: rolesanywhere.New(rolesanywhere.Options{
			Region: "us-east-1", HTTPClient: awsCredentialHTTPClient{client}, RetryMaxAttempts: 1,
		}),
	}
}

func TestAWSSigningHelperRequestAndCertificateRotation(t *testing.T) {
	for _, algorithm := range []x509.PublicKeyAlgorithm{x509.RSA, x509.ECDSA} {
		t.Run(algorithm.String(), func(t *testing.T) {
			certificate := "synthetic-first-certificate"
			var calls int
			h := awsTestSigningHelper(func(request *http.Request) (*http.Response, error) {
				calls++
				if request.Method != http.MethodPost || request.URL.Scheme != "https" ||
					request.URL.Host != "rolesanywhere.us-east-1.amazonaws.com" || request.URL.Path != "/sessions" {
					t.Fatal("CreateSession used an unexpected method or endpoint")
				}
				var body struct {
					Duration int `json:"durationSeconds"`
				}
				if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
					t.Fatal("invalid CreateSession request JSON")
				}
				query := request.URL.Query()
				if query.Get("roleArn") != testAWSRole || body.Duration != 3600 ||
					query.Get("trustAnchorArn") != "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/test" ||
					query.Get("profileArn") != "arn:aws:rolesanywhere:us-east-1:123456789012:profile/test" {
					t.Fatal("CreateSession did not preserve role, duration, trust anchor and profile")
				}
				if request.Header.Get("X-Amz-X509") != base64.StdEncoding.EncodeToString([]byte(certificate)) {
					t.Fatal("request did not use the latest certificate")
				}
				prefix := "AWS4-X509-" + algorithm.String() + "-SHA256 Credential=1/"
				if !strings.HasPrefix(request.Header.Get("Authorization"), prefix) || request.Header.Get("X-Amz-Date") == "" {
					t.Fatal("request is missing the official X.509 signature headers")
				}
				return awsTestResponse(request, http.StatusOK, awsTestSessionResponse), nil
			})
			h.certificate = func() (*tls.Certificate, error) { return awsTestCertificate(certificate, algorithm), nil }
			for _, value := range []string{"synthetic-first-certificate", "synthetic-rotated-certificate"} {
				certificate = value
				credentials, err := h.credentials(context.Background(), awsCredentialKey{testAWSRole, 3600})
				if err != nil {
					t.Fatal(err)
				}
				if credentials.Version != N1 || credentials.AccessKeyId != "test-access-key" ||
					credentials.SecretAccessKey != "test-secret-key" || credentials.SessionToken != "test-session" ||
					!credentials.Expiration.Equal(time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)) {
					t.Fatal("CreateSession credentials were not mapped to the existing response")
				}
			}
			if calls != 2 {
				t.Fatal("expected one CreateSession call per fetch")
			}
		})
	}
}

func TestAWSSigningHelperRejectsInvalidResponses(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
	}{
		{"invalid JSON", "synthetic-sensitive-diagnostic", http.StatusOK},
		{"empty credentials", `{"credentialSet":[]}`, http.StatusOK},
		{"missing credentials", `{"credentialSet":[{}]}`, http.StatusOK},
		{"invalid expiration", strings.ReplaceAll(awsTestSessionResponse, "2100-01-01T00:00:00Z", "synthetic-sensitive-diagnostic"), http.StatusOK},
		{"invalid type", `{"credentialSet":"synthetic-sensitive-diagnostic"}`, http.StatusOK},
		{"AWS failure", `{"message":"synthetic-sensitive-diagnostic"}`, http.StatusForbidden},
		{"oversized response", `{"padding":"` + strings.Repeat("x", 64*1024) + `",` + awsTestSessionResponse[1:], http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := awsTestSigningHelper(func(request *http.Request) (*http.Response, error) {
				return awsTestResponse(request, tc.status, tc.body), nil
			})
			_, err := h.credentials(context.Background(), awsCredentialKey{testAWSRole, 900})
			if err == nil || strings.Contains(err.Error(), "synthetic-sensitive-diagnostic") {
				t.Fatal("invalid response was accepted or AWS diagnostics were exposed")
			}
		})
	}
}

func TestAWSSigningHelperCertificateAndSigningFailures(t *testing.T) {
	for _, name := range []string{"reloader error", "missing certificate", "empty certificate", "invalid certificate", "missing key", "unsupported key", "signing failure"} {
		t.Run(name, func(t *testing.T) {
			h := awsTestSigningHelper(func(_ *http.Request) (*http.Response, error) {
				t.Fatal("certificate or signing failure reached the HTTP client")
				return nil, errors.New("unexpected HTTP request")
			})
			h.certificate = func() (*tls.Certificate, error) {
				pair := awsTestCertificate("synthetic-certificate", x509.RSA)
				switch name {
				case "reloader error":
					return nil, errors.New("synthetic-sensitive-diagnostic")
				case "missing certificate":
					return nil, nil
				case "empty certificate":
					pair.Certificate = nil
				case "invalid certificate":
					pair.Leaf = nil
				case "missing key":
					pair.PrivateKey = nil
				case "unsupported key":
					pair.Leaf.PublicKeyAlgorithm = x509.Ed25519
				case "signing failure":
					pair.PrivateKey = awsTestSigner{err: errors.New("synthetic-sensitive-diagnostic")}
				}
				return pair, nil
			}
			_, err := h.credentials(context.Background(), awsCredentialKey{testAWSRole, 900})
			if err == nil || strings.Contains(err.Error(), "synthetic-sensitive-diagnostic") {
				t.Fatal("certificate or signing failure was accepted or exposed diagnostics")
			}
		})
	}
}

func TestAWSSigningHelperCancellation(t *testing.T) {
	for _, beforeFetch := range []bool{false, true} {
		t.Run(map[bool]string{false: "during request", true: "before request"}[beforeFetch], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			if beforeFetch {
				cancel()
			}
			var called bool
			h := awsTestSigningHelper(func(request *http.Request) (*http.Response, error) {
				called = true
				<-request.Context().Done()
				return nil, request.Context().Err()
			})
			_, err := h.credentials(ctx, awsCredentialKey{testAWSRole, 900})
			if !errors.Is(err, ctx.Err()) || beforeFetch == called {
				t.Fatal("AWS request did not respect context cancellation")
			}
		})
	}
}

func TestAWSX509Signer(t *testing.T) {
	// These keys exist only in test memory and are never written to disk or logged.
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal("could not generate synthetic RSA key")
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("could not generate synthetic ECDSA key")
	}
	for _, key := range []crypto.Signer{rsaKey, ecKey} {
		signer := &awsX509Signer{Signer: key}
		message := []byte("synthetic-request-to-sign")
		signature, err := signer.Sign(rand.Reader, message, crypto.SHA256)
		if err != nil || signer.err != nil {
			t.Fatal("synthetic signing failed")
		}
		digest := sha256.Sum256(message)
		switch public := key.Public().(type) {
		case *rsa.PublicKey:
			if rsa.VerifyPKCS1v15(public, crypto.SHA256, digest[:], signature) != nil {
				t.Fatal("RSA signature does not verify")
			}
		case *ecdsa.PublicKey:
			if !ecdsa.VerifyASN1(public, digest[:], signature) {
				t.Fatal("ECDSA signature does not verify")
			}
		}
	}
}
