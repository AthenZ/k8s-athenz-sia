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

package main

import (
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/AthenZ/k8s-athenz-sia/v3/pkg/config"
	"github.com/AthenZ/k8s-athenz-sia/v3/pkg/identity"
	"github.com/AthenZ/k8s-athenz-sia/v3/third_party/log"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const serviceName = "athenz-sia"

var (
	VERSION    string
	BUILD_DATE string
)

// printVersion returns the version and the built date of the executable itself
func printVersion() {
	if VERSION == "" || BUILD_DATE == "" {
		fmt.Printf("(development version)\n")
	} else {
		fmt.Printf("Version: %s\n", VERSION)
		fmt.Printf("Build Date: %s\n", BUILD_DATE)
		fmt.Println("===== Default Values =====")
		fmt.Printf("Athenz Endpoint: %s\n", config.DEFAULT_ENDPOINT)
		fmt.Printf("Certificate SANs DNS Suffix: %s\n", config.DEFAULT_DNS_SUFFIX)
		fmt.Printf("Country: %s\n", config.DEFAULT_COUNTRY)
		fmt.Printf("Province: %s\n", config.DEFAULT_PROVINCE)
		fmt.Printf("Organization: %s\n", config.DEFAULT_ORGANIZATION)
		fmt.Printf("OrganizationalUnit: %s\n", config.DEFAULT_ORGANIZATIONAL_UNIT)
		fmt.Printf("Role Cert Expiry Time Buffer Minutes: %d\n", config.DEFAULT_ROLE_CERT_EXPIRY_TIME_BUFFER_MINUTES)
		fmt.Printf("Role Cert Filename Delimiter: %s\n", config.DEFAULT_ROLE_CERT_FILENAME_DELIMITER)
		fmt.Printf("Role Token Header: %s\n", config.DEFAULT_ROLE_AUTH_HEADER)
		fmt.Printf("Token Expiry: %s\n", config.DEFAULT_TOKEN_EXPIRY)
	}
}

func main() {

	// one-time logger for loading user config
	log.InitLogger("", "INFO", true)
	idConfig, err := config.LoadConfig(filepath.Base(os.Args[0]), os.Args[1:])
	if err != nil {
		switch err {
		case config.ErrHelp:
			return
		case config.ErrVersion:
			printVersion()
			return
		}
		log.Fatalln(err)
	}

	// re-init logger from user config
	log.InitLogger(filepath.Join(idConfig.LogDir, fmt.Sprintf("%s.%s.log", serviceName, idConfig.LogLevel)), idConfig.LogLevel, true)
	log.Infof("Starting [%s] with version [%s], built on [%s]", filepath.Base(os.Args[0]), VERSION, BUILD_DATE)
	log.Infof("Booting up with args: %v, config: %+v", os.Args, idConfig)

	go func() {
		log.Warn("🌟pprof server start~")
		http.ListenAndServe(":6083", nil)
	}()

	certificateChan := make(chan struct{}, 1)
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTERM, os.Interrupt)

	err, sdChan := identity.Certificated(idConfig, certificateChan)
	if err != nil {
		log.Fatalln(err)
		return
	}

	// register a metric to display the application's app_name, version and build_date
	promauto.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "sidecar_build_info",
		Help: "Indicates the application name, build version and date",
		ConstLabels: prometheus.Labels{
			"app_name": filepath.Base(os.Args[0]),
			"version":  VERSION,
			"built":    BUILD_DATE, // reference: https://github.com/enix/x509-certificate-exporter/blob/b33c43ac520dfbced529bf7543d8271d052947d0/internal/collector.go#L49
		},
	}, func() float64 {
		return float64(1)
	})

	if !idConfig.Init {
		s := <-ch // wait until receiving os.Signal from channel ch
		log.Printf("Initiating shutdown with received signal %s ...\n", s.String())
	}

	close(certificateChan)
	if sdChan != nil {
		<-sdChan
	}
	log.Println("Shutdown completed!")
}
