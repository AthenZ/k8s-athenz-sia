package identity

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/yahoo/k8s-athenz-identity/pkg/log"
)

func Tokend(idConfig *IdentityConfig, stopChan <-chan struct{}) error {

	// map[domain][role][RoleToken.TokenString]
	var roleTokenCache = make(map[string]map[string](*atomic.Value))
	// map[domain][role][AccessToken.TokenString]
	var accessTokenCache = make(map[string]map[string](*atomic.Value))

	var id *InstanceIdentity
	var keyPem []byte

	handler, err := InitIdentityHandler(idConfig)
	if err != nil {
		log.Errorf("Error while initializing handler: %s", err.Error())
		return err
	}

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

		if idConfig.TargetDomainRoles != "" {
			if idConfig.CertSecret != "" {
				log.Warnf("Attempting to load x509 cert temporary backup from kubernetes secret[%s]...", idConfig.CertSecret)

				id, keyPem, err = handler.GetX509CertFromSecret()
			}

			log.Infoln("Attempting to retrieve tokens from identity provider...")

			roleTokens, accessTokens, err := handler.GetToken(id, keyPem)
			if err != nil {
				log.Errorf("Error while retrieving tokens: %s", err.Error())
				return err
			}

			log.Infof("Successfully retrieved tokens from identity provider: len(roleTokens):%d, len(accessTokens):%d", len(roleTokens), len(accessTokens))

			for _, r := range roleTokens {
				var rt atomic.Value
				rt.Store(r)
				if roleTokenCache[r.Domain] == nil {
					roleTokenCache[r.Domain] = make(map[string](*atomic.Value))
				}
				roleTokenCache[r.Domain][r.Role] = &rt
			}
			for _, a := range accessTokens {
				var at atomic.Value
				at.Store(a)
				if accessTokenCache[a.Domain] == nil {
					accessTokenCache[a.Domain] = make(map[string](*atomic.Value))
				}
				accessTokenCache[a.Domain][a.Role] = &at
			}

			log.Infof("Successfully updated token cache from identity provider: len(roleTokenCache):%d, len(accessTokenCache):%d", len(roleTokenCache), len(accessTokenCache))
		}

		return nil
	}

	tokenHandler := func(w http.ResponseWriter, r *http.Request) {
		domainHeader := "X-Athenz-Domain"
		roleHeader := "X-Athenz-Role"
		domain := r.Header.Get(domainHeader)
		role := r.Header.Get(roleHeader)
		at, rt, response := "", "", []byte("")
		var err error

		if domain == "" || role == "" {
			message := fmt.Sprintf("http headers not set: %s[%s] %s[%s].", domainHeader, domain, roleHeader, role)
			response, err = json.Marshal(map[string]string{"error": message})
		}
		if accessTokenCache[domain] == nil || roleTokenCache[domain] == nil {
			message := fmt.Sprintf("domain[%s] was not found in cache.", domain)
			response, err = json.Marshal(map[string]string{"error": message})
		}
		if accessTokenCache[domain][role] == nil || roleTokenCache[domain][role] == nil {
			message := fmt.Sprintf("domain[%s] role[%s] was not found in cache.", domain, role)
			response, err = json.Marshal(map[string]string{"error": message})
		}

		if err != nil || len(response) > 0 {
			io.WriteString(w, fmt.Sprintf("{\"error\": \"error writing json response with: %s[%s] %s[%s] error[%v].\"}", domainHeader, domain, roleHeader, role, err))
			return
		}

		at = accessTokenCache[domain][role].Load().(*AccessToken).TokenString
		rt = roleTokenCache[domain][role].Load().(*RoleToken).TokenString
		w.Header().Set("Authorization", "bearer "+at)
		w.Header().Set("Yahoo-Role-Auth", rt)
		response, err = json.Marshal(map[string]string{"accesstoken": at, "roletoken": rt})

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
		Addr:    idConfig.TokenServerAddr,
		Handler: http.HandlerFunc(tokenHandler),
	}

	go func() {
		router := http.NewServeMux()
		router.Handle("/", http.HandlerFunc(tokenHandler))

		log.Infof("Starting Token Provider Server %s", "")
		if err := httpServer.ListenAndServe(); err != nil {
			log.Errorf("Failed to start http server: %s", err.Error())
		}
	}()

	go func() {
		t := time.NewTicker(idConfig.TokenRefresh)
		defer t.Stop()

		for {
			log.Infof("Refreshing tokens for roles[%v] in %s", idConfig.TargetDomainRoles, idConfig.TokenRefresh)
			select {
			case <-t.C:
				err := backoff.RetryNotify(tokenRequest, getExponentialBackoff(), notifyOnErr)
				if err != nil {
					log.Errorf("Failed to refresh tokens after multiple retries: %s", err.Error())
				}
			case <-stopChan:
				ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
				httpServer.SetKeepAlivesEnabled(false)
				if err := httpServer.Shutdown(ctx); err != nil {
					log.Errorf("Failed to shutdown http server: %s", err.Error())
				}
				return
			}
		}
	}()

	return nil
}
