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

package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/AthenZ/k8s-athenz-sia/pkg/config"
	"github.com/AthenZ/k8s-athenz-sia/pkg/identity"
	"github.com/AthenZ/k8s-athenz-sia/third_party/log"
)

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
		fmt.Printf("Role Cert Expiry Time Buffer Minutes: %d\n", config.DEFAULT_ROLE_CERT_EXPIRY_TIME_BUFFER_MINUTES_INT)
		fmt.Printf("Role Cert Filename Delimiter: %s\n", config.DEFAULT_ROLE_CERT_FILENAME_DELIMITER)
		fmt.Printf("Role Token Header: %s\n", config.DEFAULT_ROLE_AUTH_HEADER)
	}
}

func main() {
	flag.CommandLine.Parse([]string{}) // initialize glog with defaults
	if len(os.Args) == 2 && os.Args[1] == "version" {
		printVersion()
		return
	}

	idConfig, err := config.ReadConfig(filepath.Base(os.Args[0]), os.Args[1:])
	if err != nil {
		if err == flag.ErrHelp {
			return
		}
		log.Fatalln(err)
	}
	log.Infoln("Booting up with args", os.Args)

	certificateChan := make(chan struct{}, 1)
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTERM, os.Interrupt)

	err, sdChan := identity.Certificated(idConfig, certificateChan)
	if err != nil {
		log.Fatalln(err)
		return
	}

	if !idConfig.Init {
		<-ch // wait until receiving os.Signal from channel ch
		log.Println("Shutting down...")
	}

	close(certificateChan)
	if sdChan != nil {
		<-sdChan
	}
	log.Println("Shut down complete!")
}
