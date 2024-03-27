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
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/AthenZ/athenz/clients/go/zts"
	"github.com/AthenZ/k8s-athenz-sia/v3/pkg/config"
	"github.com/AthenZ/k8s-athenz-sia/v3/pkg/util"
	"github.com/AthenZ/k8s-athenz-sia/v3/third_party/log"
	jwt "github.com/golang-jwt/jwt/v5"
)

func newZTSClient(reloader *util.CertReloader, serverCAPath, endpoint string) (*zts.ZTSClient, error) {

	// TODO: use tls.go in sidecar: https://github.com/AthenZ/authorization-proxy/blob/6378236262dc0fbda8c00bb2d4d6544bb6e7d9d7/service/tls.go#LL71C51-L71C51
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	tlsConfig.GetClientCertificate = func(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		return reloader.GetLatestCertificate()
	}

	if serverCAPath != "" {
		certPool := x509.NewCertPool()
		caCert, err := os.ReadFile(serverCAPath)
		if err != nil {
			return nil, fmt.Errorf("Failed to load server CA certificates from local file to fetch tokens, err: %v", err)
		}
		certPool.AppendCertsFromPEM(caCert)
		tlsConfig.RootCAs = certPool
	}

	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig = tlsConfig

	// In init mode, the existing ZTS Client does not have client certificate set.
	// When config.Reloader.GetLatestCertificate() is called to load client certificate, the first certificate has not written to the file yet.
	// Therefore, ZTS Client must be renewed to make sure the ZTS Client loads the latest client certificate.
	//
	// The intermediate certificates may be different between each ZTS.
	// Therefore, ZTS Client for PostRoleCertificateRequest must share the same endpoint as PostInstanceRegisterInformation/PostInstanceRefreshInformation
	log.Infof("Create ZTS client to fetch tokens: %s, %+v", endpoint, t)
	ztsClient := zts.NewClient(endpoint, t)
	// Add User-Agent header to ZTS client for fetching tokens
	ztsClient.AddCredentials("User-Agent", config.USER_AGENT)
	return &ztsClient, nil
}

func fetchAccessToken(ztsClient *zts.ZTSClient, t CacheKey, saService string) (*AccessToken, error) {
	request := GenerateAccessTokenRequestString(t.Domain, saService, t.Role, "", "", t.ProxyForPrincipal, t.MaxExpiry)
	accessTokenResponse, err := ztsClient.PostAccessTokenRequest(zts.AccessTokenRequest(request))
	if err != nil || accessTokenResponse.Access_token == "" {
		return nil, fmt.Errorf("PostAccessTokenRequest failed for target [%s], err: %v", t.String(), err)
	}
	tok, _, err := jwt.NewParser().ParseUnverified(accessTokenResponse.Access_token, &jwt.RegisteredClaims{})
	if err != nil {
		return nil, fmt.Errorf("jwt.ParseUnverified() err: %v", err)
	}

	expTime, err := tok.Claims.GetExpirationTime()
	if err != nil {
		return nil, fmt.Errorf("jwt.GetExpirationTime() err: %v", err)
	}

	return &AccessToken{
		domain: t.Domain,
		role:   t.Role,
		raw:    accessTokenResponse.Access_token,
		expiry: expTime.Unix(),
		scope:  accessTokenResponse.Scope,
	}, nil
}

func fetchRoleToken(ztsClient *zts.ZTSClient, t CacheKey) (*RoleToken, error) {
	var minExpiry, maxExpiry *int32
	if t.MinExpiry > 0 {
		e := int32(t.MinExpiry)
		minExpiry = &e
	}
	// To prevent the Role Token's expiration from being shorter than the ZTS server's default value,
	// we will ignore the maxExpiry setting value in the request body.
	// if t.MaxExpiry > 0 {
	// 	e := int32(t.MaxExpiry)
	// 	maxExpiry = &e
	// }
	roletokenResponse, err := ztsClient.GetRoleToken(zts.DomainName(t.Domain), zts.EntityList(t.Role), minExpiry, maxExpiry, zts.EntityName(t.ProxyForPrincipal))
	if err != nil || roletokenResponse.Token == "" {
		return nil, fmt.Errorf("GetRoleToken failed for target [%s], err: %v", t.String(), err)
	}
	return &RoleToken{
		domain: t.Domain,
		role:   t.Role,
		raw:    roletokenResponse.Token,
		expiry: roletokenResponse.ExpiryTime,
	}, nil
}

// GenerateAccessTokenRequestString generates and urlencodes an access token string.
// TODO: fix the original method: https://github.com/AthenZ/athenz/blob/a85f48666763759ee28fda114acc4c8d2cafc28e/libs/go/athenzutils/ztsclient.go#L68
func GenerateAccessTokenRequestString(domain, service, roles, authzDetails, proxyPrincipalSpiffeUris, proxyForPrincipal string, expiryTime int) string {

	params := url.Values{}
	params.Add("grant_type", "client_credentials")
	// do not include the expiry param if the client is asking
	// for the server default setting (expiryTime == 0) or any
	// invalid values (expiryTime < 0)
	if expiryTime > 0 {
		params.Add("expires_in", strconv.Itoa(expiryTime))
	}

	var scope string
	if roles == "" {
		scope = domain + ":domain"
	} else {
		roleList := strings.Split(roles, ",")
		for idx, role := range roleList {
			if idx != 0 {
				scope += " "
			}
			scope += domain + ":role." + role
		}
	}
	if service != "" {
		scope += " openid " + domain + ":service." + service
	}

	params.Add("scope", scope)
	if authzDetails != "" {
		params.Add("authorization_details", authzDetails)
	}
	if proxyPrincipalSpiffeUris != "" {
		params.Add("proxy_principal_spiffe_uris", proxyPrincipalSpiffeUris)
	}
	if proxyForPrincipal != "" {
		params.Add("proxy_for_principal", proxyForPrincipal)
	}
	return params.Encode()
}
