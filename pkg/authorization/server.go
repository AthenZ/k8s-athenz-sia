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

package authorization

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	authorizerd "github.com/AthenZ/athenz-authorizer/v5"
	"github.com/pkg/errors"

	"github.com/AthenZ/k8s-athenz-sia/v3/third_party/log"
)

// AuthorizationConfig holds configuration for the authorization server
type AuthorizationConfig struct {
	// Server configuration
	ServerAddr                        string
	PolicyDomains                     string
	TokenType                         string

	// Refresh intervals
	PolicyRefreshInterval             time.Duration
	PublicKeyRefreshInterval          time.Duration
	CacheInterval                     time.Duration

	// Athenz configuration
	AthenzURL                         string
	HTTPClient                        *http.Client
	RoleAuthHeader                    string
	EnableMTLSCertificateBoundAccessToken bool
}

// AuthorizationServer represents the authorization server
type AuthorizationServer struct {
	config     *AuthorizationConfig
	daemon     authorizerd.Authorizerd
	httpServer *http.Server
	stopChan   <-chan struct{}
}

// NewAuthorizationServer creates a new authorization server instance
func NewAuthorizationServer(config *AuthorizationConfig, stopChan <-chan struct{}) *AuthorizationServer {
	return &AuthorizationServer{
		config:   config,
		stopChan: stopChan,
	}
}

// Start initializes and starts the authorization server
func (as *AuthorizationServer) Start(ctx context.Context) error {
	if as.config.ServerAddr == "" || as.config.PolicyDomains == "" || as.config.TokenType == "" {
		log.Infof("Authorizer is disabled with empty options: address[%s], domains[%s], authorizer-type[%s]",
			as.config.ServerAddr, as.config.PolicyDomains, as.config.TokenType)
		return nil
	}

	// Parse Athenz URL
	authorizerURL, err := url.Parse(as.config.AthenzURL)
	if err != nil {
		return fmt.Errorf("failed to parse athenz URL[%s]: %w", as.config.AthenzURL, err)
	}

	// Initialize authorizerd daemon
	daemon, err := authorizerd.New(
		authorizerd.WithAthenzURL(authorizerURL.Host+authorizerURL.Path),
		authorizerd.WithHTTPClient(as.config.HTTPClient),
		authorizerd.WithAthenzDomains(strings.Split(as.config.PolicyDomains, ",")...),
		authorizerd.WithPolicyRefreshPeriod(as.config.PolicyRefreshInterval.String()),
		authorizerd.WithPubkeyRefreshPeriod(as.config.PublicKeyRefreshInterval.String()),
		authorizerd.WithCacheExp(as.config.CacheInterval),
		authorizerd.WithEnablePolicyd(),
		authorizerd.WithEnableJwkd(),
		authorizerd.WithAccessTokenParam(authorizerd.NewAccessTokenParam(true, as.config.EnableMTLSCertificateBoundAccessToken, "", "", false, nil)),
		authorizerd.WithEnableRoleToken(),
		authorizerd.WithRoleAuthHeader(as.config.RoleAuthHeader),
		authorizerd.WithEnableTokenCache(), // Enable token validation caching
	)
	if err != nil {
		return fmt.Errorf("failed to initialize authorizer: %w", err)
	}

	as.daemon = daemon

	// Start the authorization daemon
	go func() {
		log.Infof("Starting authorizer: domains[%s]", as.config.PolicyDomains)
		for err := range daemon.Start(ctx) {
			log.Errorf("Failed to get initial authorizers after multiple retries: %s", err.Error())
		}
	}()

	// Initialize daemon
	if err = daemon.Init(ctx); err != nil {
		return fmt.Errorf("failed to start authorizer: %w", err)
	}

	// Create HTTP server with handler
	as.httpServer = &http.Server{
		Addr:    as.config.ServerAddr,
		Handler: http.HandlerFunc(as.authorizationHandler),
	}

	// Start HTTP server
	go func() {
		log.Infof("Starting authorization server: address[%s]", as.config.ServerAddr)
		if err := as.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Errorf("Failed to start authorization server: %s", err.Error())
		}
	}()

	// Wait for stop signal
	go func() {
		<-as.stopChan
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		as.httpServer.SetKeepAlivesEnabled(false)
		if err := as.httpServer.Shutdown(shutdownCtx); err != nil {
			log.Errorf("Failed to shutdown authorization server: %s", err.Error())
		}
	}()

	return nil
}

// authorizationHandler handles authorization requests
func (as *AuthorizationServer) authorizationHandler(w http.ResponseWriter, r *http.Request) {
	const (
		actionHeader      = "X-Athenz-Action"
		resourceHeader    = "X-Athenz-Resource"
		accessTokenHeader = "Authorization"
		certificateHeader = "X-Athenz-Certificate"
	)

	// Extract headers
	action := r.Header.Get(actionHeader)
	resource := r.Header.Get(resourceHeader)

	accessTokenHeaderValue := strings.Split(r.Header.Get(accessTokenHeader), " ")
	accessToken := accessTokenHeaderValue[len(accessTokenHeaderValue)-1]

	roleToken := r.Header.Get(as.config.RoleAuthHeader)

	certificatePEM, _ := url.QueryUnescape(r.Header.Get(certificateHeader))

	// Validate required headers
	if (accessToken == "" && roleToken == "" && certificatePEM == "") || action == "" || resource == "" {
		log.Infof("Required http headers are not set: %s len(%d), %s len(%d), %s len(%d), action[%s], resource[%s]",
			accessTokenHeader, len(accessToken), as.config.RoleAuthHeader, len(roleToken),
			certificateHeader, len(certificatePEM), action, resource)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Parse certificate if provided
	var cert *x509.Certificate
	if certificatePEM != "" {
		block, _ := pem.Decode([]byte(certificatePEM))
		if block == nil {
			log.Infof("Malformed PEM certificate was set: %s[%s]", certificateHeader, certificatePEM)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		var err error
		cert, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.Infof("Malformed X.509 certificate was set: %s[%s]", certificateHeader, certificatePEM)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
	}

	// Perform authorization
	ctx := context.Background()
	principal, err := as.authorize(ctx, cert, accessToken, roleToken, action, resource)
	if err != nil || principal == nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Set response headers
	w.Header().Set("X-Athenz-Principal", principal.Name())
	w.Header().Set("X-Athenz-Domain", principal.Domain())
	w.Header().Set("X-Athenz-Role", strings.Join(principal.Roles(), ","))
	w.Header().Set("X-Athenz-Issued-At", fmt.Sprintf("%d", principal.IssueTime()))
	w.Header().Set("X-Athenz-Expires-At", fmt.Sprintf("%d", principal.ExpiryTime()))
	w.Header().Set("X-Athenz-AuthorizedRoles", strings.Join(principal.AuthorizedRoles(), ","))

	if c, ok := principal.(authorizerd.OAuthAccessToken); ok {
		w.Header().Set("X-Athenz-Client-ID", c.ClientID())
	}

	// Prepare JSON response
	result := map[string]string{
		"principal":        principal.Name(),
		"domain":          principal.Domain(),
		"role":            strings.Join(principal.Roles(), ","),
		"issued-at":       fmt.Sprintf("%d", principal.IssueTime()),
		"expires-at":      fmt.Sprintf("%d", principal.ExpiryTime()),
		"authorizedroles": strings.Join(principal.AuthorizedRoles(), ","),
	}

	response, err := json.Marshal(result)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Infof("Authorization succeeded but failed to prepare response: %s", err.Error())
		return
	}

	w.WriteHeader(http.StatusOK)
	io.WriteString(w, string(response))
}

// authorize performs authorization using multiple methods (certificate, access token, role token)
func (as *AuthorizationServer) authorize(ctx context.Context, cert *x509.Certificate, accessToken, roleToken, action, resource string) (authorizerd.Principal, error) {
	// Try role certificate first
	if cert != nil && accessToken == "" {
		principal, err := as.daemon.AuthorizeRoleCert(ctx, []*x509.Certificate{cert}, action, resource)
		if err != nil {
			log.Debugf("Authorization failed with role certificate, action[%s], resource[%s]: %s", action, resource, err.Error())
		} else if principal != nil {
			return principal, nil
		}
	}

	// Try access token
	if accessToken != "" {
		principal, err := as.daemon.AuthorizeAccessToken(ctx, accessToken, action, resource, cert)
		if err != nil {
			log.Debugf("Authorization failed with access token, action[%s], resource[%s]: %s", action, resource, err.Error())
		} else if principal != nil {
			return principal, nil
		}
	}

	// Try role token
	if roleToken != "" {
		principal, err := as.daemon.AuthorizeRoleToken(ctx, roleToken, action, resource)
		if err != nil {
			log.Debugf("Authorization failed with role token, action[%s], resource[%s]: %s", action, resource, err.Error())
		} else if principal != nil {
			return principal, nil
		}
	}

	return nil, errors.New("authorization failed with all methods")
}