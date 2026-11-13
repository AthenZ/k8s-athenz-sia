// Copyright 2026 The Athenz Authors
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

package imds

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/AthenZ/athenz/clients/go/zts"
	"github.com/AthenZ/k8s-athenz-sia/v3/pkg/config"
)

type credentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Expiration      time.Time
}

type credentialSource interface {
	Get(context.Context) (credentials, error)
}

type fileSource struct{ path string }

// Read the shared credentials file on each request so another process can
// rotate its credentials without restarting SIA.
func (s fileSource) Get(_ context.Context) (credentials, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return credentials{}, err
	}
	var result credentials
	inDefault := false
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			inDefault = strings.EqualFold(line, "[default]")
			continue
		}
		if !inDefault {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "aws_access_key_id":
			result.AccessKeyID = strings.TrimSpace(value)
		case "aws_secret_access_key":
			result.SecretAccessKey = strings.TrimSpace(value)
		case "aws_session_token":
			result.SessionToken = strings.TrimSpace(value)
		case "expiration":
			result.Expiration, err = time.Parse(time.RFC3339, strings.TrimSpace(value))
			if err != nil {
				return credentials{}, fmt.Errorf("invalid AWS credentials expiration: %w", err)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return credentials{}, err
	}
	if result.AccessKeyID == "" || result.SecretAccessKey == "" {
		return credentials{}, fmt.Errorf("AWS credentials file has no access key or secret key")
	}
	if result.Expiration.IsZero() {
		result.Expiration = time.Now().UTC().Add(time.Hour)
	}
	return result, nil
}

type ztsSource struct {
	client   zts.ZTSClient
	domain   string
	role     string
	duration int32
}

func newZTSSource(idCfg *config.IdentityConfig) (credentialSource, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return idCfg.Reloader.GetLatestCertificate()
		},
	}
	if idCfg.ServerCACert != "" {
		pem, err := os.ReadFile(idCfg.ServerCACert)
		if err != nil {
			return nil, fmt.Errorf("read ZTS CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("ZTS CA file contains no certificates")
		}
		tlsConfig.RootCAs = pool
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig
	transport.ResponseHeaderTimeout = 10 * time.Second
	return ztsSource{
		client:   zts.NewClient(idCfg.Endpoint, transport),
		domain:   idCfg.IMDSServer.Domain,
		role:     idCfg.IMDSServer.Role,
		duration: int32(idCfg.IMDSServer.DurationSeconds),
	}, nil
}

func (s ztsSource) Get(_ context.Context) (credentials, error) {
	var duration *int32
	if s.duration > 0 {
		duration = &s.duration
	}
	result, err := s.client.GetAWSTemporaryCredentials(zts.DomainName(s.domain), zts.AWSArnRoleName(s.role), duration, "")
	if err != nil {
		return credentials{}, err
	}
	if result == nil {
		return credentials{}, fmt.Errorf("ZTS returned no AWS credentials")
	}
	return credentials{
		AccessKeyID:     result.AccessKeyId,
		SecretAccessKey: result.SecretAccessKey,
		SessionToken:    result.SessionToken,
		Expiration:      result.Expiration.Time,
	}, nil
}
