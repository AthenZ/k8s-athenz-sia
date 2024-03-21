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
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// RegisterBuildInfo registers a metric to display the application's app_name, version and build_date
func RegisterBuildInfo(appName, version, buildDate string) {
	promauto.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "sidecar_build_info",
		Help: "Indicates the application name, build version and date",
		ConstLabels: prometheus.Labels{
			"app_name": appName,
			"version":  version,
			"built":    buildDate, // reference: https://github.com/enix/x509-certificate-exporter/blob/b33c43ac520dfbced529bf7543d8271d052947d0/internal/collector.go#L49
		},
	}, func() float64 {
		return float64(1)
	})
}
