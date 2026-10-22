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

package metrics

import (
	"context"
	"crypto/x509"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/AthenZ/k8s-athenz-sia/v3/pkg/config"
	"github.com/AthenZ/k8s-athenz-sia/v3/third_party/log"
	"github.com/enix/x509-certificate-exporter/v4/pkg/cert"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
)

func TestMetricsDisabled(t *testing.T) {
	log.InitLogger(filepath.Join(t.TempDir(), "metrics.log"), "error", false)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	d, err := New(ctx, &config.IdentityConfig{})
	require.NoError(t, err)
	require.Nil(t, d)

	for _, cfg := range []*config.IdentityConfig{
		{Init: true, MetricsServerAddr: "127.0.0.1:9999"},
		{},
	} {
		d, err := New(context.Background(), cfg)
		require.NoError(t, err)
		require.Nil(t, d.(*metricsService).server)
		require.NoError(t, d.Start(context.Background()))
		d.Shutdown()
	}
}

func TestMetricsCertificatePaths(t *testing.T) {
	log.InitLogger(filepath.Join(t.TempDir(), "metrics.log"), "error", false)
	for _, mode := range []string{"empty", "local", "copper", "ca", "role", "symlink"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			servicePath := filepath.Join(dir, "service.pem")
			caPath := filepath.Join(dir, "ca.pem")
			rolePath := filepath.Join(dir, "example.reader.pem")
			for _, path := range []string{servicePath, caPath, rolePath} {
				// Invalid input exercises path selection without certificate material.
				require.NoError(t, os.WriteFile(path, []byte("test input"), 0600))
			}
			cfg := &config.IdentityConfig{MetricsServerAddr: "127.0.0.1:9999"}
			var expected []string
			switch mode {
			case "empty":
				cfg.ServiceCert.LocalCert.Use = true
			case "local":
				cfg.ServiceCert.LocalCert = config.LocalCertMode{Use: true, CertPath: servicePath}
				expected = []string{servicePath}
			case "copper":
				cfg.ServiceCert.CopperArgos = config.CopperArgosMode{
					Use: true, Cert: config.X509File{Paths: []string{servicePath}},
				}
				expected = []string{servicePath}
			case "ca":
				cfg.CaCertFile = caPath
				expected = []string{caPath}
			case "role":
				cfg.RoleCert = config.DerivedRoleCert{
					Use: true, Format: filepath.Join(dir, "{{domain}}.{{role}}.pem"),
					TargetDomainRoles: []config.DomainRole{{Domain: "example", Role: "reader"}},
				}
				expected = []string{rolePath}
			case "symlink":
				link := filepath.Join(dir, "linked.pem")
				require.NoError(t, os.Symlink(servicePath, link))
				cfg.ServiceCert.LocalCert = config.LocalCertMode{Use: true, CertPath: link}
				expected = []string{link}
			}

			d, err := New(context.Background(), cfg)
			require.NoError(t, err)
			ms := d.(*metricsService)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- ms.source.Run(ctx, ms.exporter) }()
			select {
			case <-ms.firstSyncDone:
			case <-ctx.Done():
				t.Fatal("initial file scan did not finish")
			}
			cancel()
			select {
			case err := <-done:
				require.ErrorIs(t, err, context.Canceled)
			case <-time.After(5 * time.Second):
				t.Fatal("file source did not stop")
			}
			require.Equal(t, len(expected), ms.exporter.Stats().TotalBundles)
			for _, path := range expected {
				ms.exporter.Delete(cert.SourceRef{Kind: cert.KindFile, Location: path})
			}
			require.Zero(t, ms.exporter.Stats().TotalBundles)
			ms.Shutdown()
		})
	}
}

func TestMetricsStartScrapeShutdown(t *testing.T) {
	log.InitLogger(filepath.Join(t.TempDir(), "metrics.log"), "error", false)
	oldRegisterer, oldGatherer := prometheus.DefaultRegisterer, prometheus.DefaultGatherer
	defaultRegistry := prometheus.NewRegistry()
	prometheus.DefaultRegisterer, prometheus.DefaultGatherer = defaultRegistry, defaultRegistry
	t.Cleanup(func() {
		prometheus.DefaultRegisterer, prometheus.DefaultGatherer = oldRegisterer, oldGatherer
	})
	RegisterBuildInfo("test-sia", "test-version", "test-date")
	for _, name := range []string{"cached_token_bytes", "cached_token_entries"} {
		g := prometheus.NewGauge(prometheus.GaugeOpts{Name: name, Help: "Test metric."})
		defaultRegistry.MustRegister(g)
		g.Set(1)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := listener.Addr().String()
	require.NoError(t, listener.Close())
	d, err := New(context.Background(), &config.IdentityConfig{MetricsServerAddr: addr})
	require.NoError(t, err)
	ms := d.(*metricsService)
	t.Cleanup(ms.Shutdown)
	require.NoError(t, ms.Start(context.Background()))
	select {
	case <-ms.firstSyncDone:
	default:
		t.Fatal("server started before initial file scan")
	}
	// Synthetic metadata verifies enabled metric families without loading a certificate.
	ms.exporter.Upsert(cert.Bundle{
		Source: cert.SourceRef{Kind: cert.KindFile, Location: "/test.pem", SourceName: "files", Format: cert.FormatPEM},
		Items: []cert.Item{{Cert: &x509.Certificate{
			SerialNumber: big.NewInt(1), NotBefore: time.Unix(1600000000, 0), NotAfter: time.Unix(4100000000, 0),
		}}},
	})
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://" + addr + "/metrics")
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	for _, name := range []string{
		"sidecar_build_info", "cached_token_bytes", "cached_token_entries",
		"x509_cert_not_before", "x509_cert_not_after", "x509_cert_expired",
		"x509_cert_expires_in_seconds", "x509_cert_valid_since_seconds", "x509_cert_error",
		"x509_source_errors_total",
	} {
		require.Contains(t, string(body), "# TYPE "+name+" ")
	}
	require.NotContains(t, string(body), "x509_read_errors")
}
