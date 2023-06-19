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
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"

	"github.com/AthenZ/athenz/clients/go/zts"
	"github.com/AthenZ/athenz/libs/go/athenzutils"
	"github.com/AthenZ/k8s-athenz-sia/v3/third_party/log"
)

func newZTSClient(keyPath, certPath, serverCAPath, endpoint string) (*zts.ZTSClient, error) {

	// TODO: use tls.go in sidecar: https://github.com/AthenZ/authorization-proxy/blob/6378236262dc0fbda8c00bb2d4d6544bb6e7d9d7/service/tls.go#LL71C51-L71C51
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
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
	tlsConfig.GetClientCertificate = func(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		log.Debugf("Attempting to load client x509 certificate from local file to fetch tokens: key[%s], cert[%s]...", keyPath, certPath)
		certPem, err := os.ReadFile(certPath)
		if err != nil {
			log.Warnf("Error while reading client x509 certificate from local file[%s]: %s", certPath, err.Error())
			return nil, err
		}
		keyPem, err := os.ReadFile(keyPath)
		if err != nil {
			log.Warnf("Error while reading client x509 certificate key from local file[%s]: %s", keyPath, err.Error())
			return nil, err
		}
		cert, err := tls.X509KeyPair(certPem, keyPem)
		if err != nil {
			return nil, fmt.Errorf("Failed to client x509 certificate from local file to fetch tokens, err: %v", err)
		}

		log.Debugf("Successfully loaded client x509 certificate from local file to fetch tokens: key size[%d]bytes, certificate size[%d]bytes", len(keyPem), len(certPem))
		return &cert, nil
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
	return &ztsClient, nil
}

func fetchAccessToken(ztsClient *zts.ZTSClient, t CacheKey, saService string) (*AccessToken, error) {
	request := athenzutils.GenerateAccessTokenRequestString(t.Domain, saService, t.Role, "", "", int(t.MinExpiry))
	accessTokenResponse, err := ztsClient.PostAccessTokenRequest(zts.AccessTokenRequest(request))
	if err != nil || accessTokenResponse.Access_token == "" {
		return nil, fmt.Errorf("PostAccessTokenRequest failed for target [%s], err: %v", t.String(), err)
	}
	return &AccessToken{
		domain: t.Domain,
		role:   t.Role,
		raw:    accessTokenResponse.Access_token,
		expiry: int64(*accessTokenResponse.Expires_in),
	}, nil
}

func fetchRoleToken(ztsClient *zts.ZTSClient, t CacheKey) (*RoleToken, error) {
	var minExpiry, maxExpiry *int32
	if t.MinExpiry != 0 {
		e := int32(t.MinExpiry)
		minExpiry = &e
	}
	if t.MaxExpiry != 0 {
		e := int32(t.MaxExpiry)
		maxExpiry = &e
	}
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
