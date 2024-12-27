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
	"context"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/AthenZ/k8s-athenz-sia/v3/pkg/certificate"
	"github.com/AthenZ/k8s-athenz-sia/v3/pkg/config"
	"github.com/AthenZ/k8s-athenz-sia/v3/pkg/healthcheck"
	"github.com/AthenZ/k8s-athenz-sia/v3/pkg/metrics"
	"github.com/AthenZ/k8s-athenz-sia/v3/pkg/token"
	"github.com/AthenZ/k8s-athenz-sia/v3/third_party/log"
)

// printVersion returns the version and the built date of the executable itself
func printVersion() {
	if config.VERSION == "" || config.BUILD_DATE == "" {
		fmt.Printf("(development version)\n")
	} else {
		fmt.Printf("Version: %s\n", config.VERSION)
		fmt.Printf("Build Date: %s\n", config.BUILD_DATE)
		fmt.Println("===== Default Values =====")
		fmt.Printf("Athenz Endpoint: %s\n", config.DEFAULT_ENDPOINT)
		fmt.Printf("Certificate SANs DNS Suffix: %s\n", config.DEFAULT_DNS_SUFFIX)
		fmt.Printf("Country: %s\n", config.DEFAULT_COUNTRY)
		fmt.Printf("Province: %s\n", config.DEFAULT_PROVINCE)
		fmt.Printf("Organization: %s\n", config.DEFAULT_ORGANIZATION)
		fmt.Printf("OrganizationalUnit: %s\n", config.DEFAULT_ORGANIZATIONAL_UNIT)
		fmt.Printf("Role Cert Expiry Time Buffer Minutes: %d\n", config.DEFAULT_ROLE_CERT_EXPIRY_TIME_BUFFER_MINUTES)
		fmt.Printf("Role Cert Filename Delimiter: %s\n", config.DEFAULT_ROLE_CERT_FILENAME_DELIMITER)
		fmt.Printf("Access Token Filename Delimiter: %s\n", config.DEFAULT_ACCESS_TOKEN_FILENAME_DELIMITER)
		fmt.Printf("Role Token Filename Delimiter: %s\n", config.DEFAULT_ROLE_TOKEN_FILENAME_DELIMITER)
		fmt.Printf("Role Token Header: %s\n", config.DEFAULT_ROLE_AUTH_HEADER)
		fmt.Printf("Token Expiry: %s\n", config.DEFAULT_TOKEN_EXPIRY)
	}
}

// main should handles MODE=init/refresh, underlying daemon should NOT handle it
func main() {

	// one-time logger for loading user config
	log.InitLogger("", "INFO", true)
	idCfg, err := config.LoadConfig(config.APP_NAME, os.Args[1:])
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
	log.InitLogger(filepath.Join(idCfg.LogDir, fmt.Sprintf("%s.%s.log", config.APP_NAME, idCfg.LogLevel)), idCfg.LogLevel, true)
	log.Infof("Starting [%s] with version [%s], built on [%s]", config.APP_NAME, config.VERSION, config.BUILD_DATE)
	log.Infof("Booting up with args: %v, config: %+v", os.Args, idCfg)

	// delay boot with jitter
	if idCfg.DelayJitterSeconds != 0 {
		sleep := time.Duration(rand.Int63n(idCfg.DelayJitterSeconds)) * time.Second
		log.Infof("Delaying boot with jitter [%s] randomized from [%s]...", sleep, time.Duration(idCfg.DelayJitterSeconds)*time.Second)
		time.Sleep(sleep)
	}

	// register metrics
	metrics.RegisterBuildInfo(filepath.Base(os.Args[0]), config.VERSION, config.BUILD_DATE)

	// variables
	causeBySignal := fmt.Errorf("received signal")
	causeByStartFailed := fmt.Errorf("start failed")
	initCtx, cancelInit := context.WithCancelCause(context.Background())
	runCtx, cancelRun := context.WithCancelCause(context.Background())

	// signal handling in background
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, os.Interrupt)
	go func() {
		// wait for a signal, then cancel contexts
		sigGot := <-sigChan
		log.Infof("Received signal: %s", sigGot.String())
		cancelInit(fmt.Errorf("%w: %s", causeBySignal, sigGot))
		cancelRun(fmt.Errorf("%w: %s", causeBySignal, sigGot))
	}()

	// initiate background services
	certService, err := certificate.New(initCtx, idCfg)
	if err != nil {
		log.Fatalf("Error initiating certificate provider: %s", err.Error())
	}
	tokenService, err := token.New(initCtx, idCfg)
	if err != nil {
		log.Fatalf("Error initiating token provider: %s", err.Error())
	}
	metricsService, err := metrics.New(initCtx, idCfg)
	if err != nil {
		log.Fatalf("Error initiating metrics exporter: %s", err.Error())
	}
	hcService, err := healthcheck.New(initCtx, idCfg)
	if err != nil {
		log.Fatalf("Error initiating health check: %s", err.Error())
	}

	// mode=init, end the process
	if initCtx.Err() != nil {
		log.Infof("Init stopped by cause: %s", context.Cause(initCtx).Error())
		return
	}
	if idCfg.Init {
		log.Infoln("Init completed!")
		return
	}

	// start background services, should process the sequences in order and graceful shutdown if any start failed
	if err := certService.Start(runCtx); err != nil {
		log.Errorf("Error starting certificate provider: %s", err.Error())
		cancelRun(fmt.Errorf("%w: %w", causeByStartFailed, err))
	}
	if err := tokenService.Start(runCtx); err != nil {
		log.Errorf("Error starting token provider: %s", err.Error())
		cancelRun(fmt.Errorf("%w: %w", causeByStartFailed, err))
	}
	if err := metricsService.Start(runCtx); err != nil {
		log.Errorf("Error starting metrics exporter: %s", err.Error())
		cancelRun(fmt.Errorf("%w: %w", causeByStartFailed, err))
	}
	if err := hcService.Start(runCtx); err != nil {
		log.Errorf("Error starting health check: %s", err.Error())
		cancelRun(fmt.Errorf("%w: %w", causeByStartFailed, err))
	}

	// mode=refresh, wait for signal and then shutdown gracefully
	<-runCtx.Done()
	log.Infof("Initiating shutdown by cause: %s ...", context.Cause(runCtx).Error())
	hcService.Shutdown()
	metricsService.Shutdown()
	tokenService.Shutdown()
	certService.Shutdown()

	if errors.Is(context.Cause(runCtx), causeByStartFailed) {
		log.Fatalf("Start failed by cause: %s", context.Cause(runCtx).Error())
	}
	log.Infoln("Shutdown completed!")
}
