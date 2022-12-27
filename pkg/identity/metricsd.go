package identity

import (
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/yahoo/k8s-athenz-identity/pkg/log"
)

func Metricsd(idConfig *IdentityConfig, stopChan <-chan struct{}) error {

	// getExponentialBackoff will return a backoff config with first retry delay of 5s, and backoff retry
	// until params.refresh / 4
	getExponentialBackoff := func() *backoff.ExponentialBackOff {
		b := backoff.NewExponentialBackOff()
		b.InitialInterval = 5 * time.Second
		b.Multiplier = 2
		b.MaxElapsedTime = idConfig.Refresh / 4
		return b
	}

	notifyOnErr := func(err error, backoffDelay time.Duration) {
		log.Errorf("Failed to create/refresh cert: %s. Retrying in %s", err.Error(), backoffDelay)
	}

	tokenRequest := func() error {

		return nil
	}

	metricsHandler := func(w http.ResponseWriter, r *http.Request) {
		response := []byte("")

		io.WriteString(w, fmt.Sprintf("%s", response))
	}

	if !idConfig.Init {
		err := backoff.RetryNotify(tokenRequest, getExponentialBackoff(), notifyOnErr)
		if err != nil {
			log.Errorf("Failed to retrieve tokens after multiple retries: %s", err.Error())

			return err
		}
	}

	httpServer := &http.Server{
		Addr:    idConfig.MetricsServerAddr,
		Handler: http.HandlerFunc(metricsHandler),
	}

	go func() {
		log.Infof("Starting Token Provider Server %s", "")

		if err := httpServer.ListenAndServe(); err != nil {
			log.Errorf("Failed to start http server: %s", err.Error())
		}
	}()

	return nil
}
