package identity

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/pkg/errors"
	"github.com/yahoo/k8s-athenz-identity/pkg/log"
	"github.com/yahoo/k8s-athenz-identity/pkg/util"
)

func Tokend(idConfig *IdentityConfig, stopChan <-chan struct{}) error {

	if idConfig.TokenServerAddr == "" || idConfig.TargetDomainRoles == "" || idConfig.TokenType == "" {
		log.Infof("Token provider is disabled with empty options: address[%s], roles[%s], token-type[%s]", idConfig.TokenServerAddr, idConfig.TargetDomainRoles, idConfig.TokenType)
		return nil
	}

	// map[domain][role][RoleToken.TokenString]
	var roleTokenCache = make(map[string]map[string](*atomic.Value))
	// map[domain][role][AccessToken.TokenString]
	var accessTokenCache = make(map[string]map[string](*atomic.Value))

	var keyPem, certPem []byte

	handler, err := InitIdentityHandler(idConfig)
	if err != nil {
		log.Errorf("Failed to initialize client for tokens: %s", err.Error())
		return err
	}

	writeFiles := func() error {

		w := util.NewWriter()

		for domain, atdcache := range accessTokenCache {
			for role, atrcache := range atdcache {
				at := atrcache.Load().(*AccessToken).TokenString
				log.Infof("[New Access Token] Domain: %s, Role: %s", domain, role)
				outPath := filepath.Join(idConfig.TokenDir, domain+":role."+role+".accesstoken")
				log.Debugf("Saving Access Token[%d bytes] at %s", len(at), outPath)
				if err := w.AddBytes(outPath, 0644, []byte(at)); err != nil {
					return errors.Wrap(err, "unable to save access token")
				}
			}
		}
		for domain, rtdcache := range roleTokenCache {
			for role, rtrcache := range rtdcache {
				rt := rtrcache.Load().(*RoleToken).TokenString
				log.Infof("[New Role Token] Domain: %s, Role: %s", domain, role)
				outPath := filepath.Join(idConfig.TokenDir, domain+":role."+role+".roletoken")
				log.Debugf("Saving Role Token[%d bytes] at %s", len(rt), outPath)
				if err := w.AddBytes(outPath, 0644, []byte(rt)); err != nil {
					return errors.Wrap(err, "unable to save role token")
				}
			}
		}

		return w.Save()
	}

	// getExponentialBackoff will return a backoff config with first retry delay of 5s, and backoff retry
	// until TOKEN_REFRESH_INTERVAL / 4
	getExponentialBackoff := func() *backoff.ExponentialBackOff {
		b := backoff.NewExponentialBackOff()
		b.InitialInterval = 5 * time.Second
		b.Multiplier = 2
		b.MaxElapsedTime = idConfig.TokenRefresh / 4
		return b
	}

	notifyOnErr := func(err error, backoffDelay time.Duration) {
		log.Errorf("Failed to refresh tokens: %s. Retrying in %s", err.Error(), backoffDelay)
	}

	run := func() error {

		log.Debugf("Attempting to load x509 certificate from local file to get tokens: key[%s], cert[%s]...", idConfig.KeyFile, idConfig.CertFile)

		certPem, err = os.ReadFile(idConfig.CertFile)
		if err != nil {
			log.Warnf("Error while reading x509 certificate from local file[%s]: %s", idConfig.CertFile, err.Error())
		}
		keyPem, err = os.ReadFile(idConfig.KeyFile)
		if err != nil {
			log.Warnf("Error while reading x509 certificate key from local file[%s]: %s", idConfig.KeyFile, err.Error())
		}

		if len(certPem) == 0 || len(keyPem) == 0 {
			log.Errorf("Failed to load x509 certificate from local file to get tokens: key size[%d]bytes, certificate size[%d]bytes", len(keyPem), len(certPem))
			return nil
		} else {

			log.Debugf("Successfully loaded x509 certificate from local file to get tokens: key size[%d]bytes, certificate size[%d]bytes", len(keyPem), len(certPem))

		}

		log.Infof("Attempting to get tokens from identity provider: targets[%s]...", idConfig.TargetDomainRoles)

		roleTokens, accessTokens, err := handler.GetToken(certPem, keyPem)
		if err != nil {
			log.Warnf("Error while requesting tokens: %s", err.Error())
			return err
		}

		log.Debugf("Successfully received tokens from identity provider: roleTokens(%d), accessTokens(%d)", len(roleTokens), len(accessTokens))

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

		log.Infof("Successfully updated token cache: roleTokens(%d), accessTokens(%d)", len(roleTokens), len(accessTokens))

		if idConfig.TokenDir != "" {
			return writeFiles()
		} else {

			log.Debugf("Skipping to write token files to directory[%s]", idConfig.TokenDir)

			return nil
		}
	}

	tokenHandler := func(w http.ResponseWriter, r *http.Request) {
		domainHeader := "X-Athenz-Domain"
		roleHeader := "X-Athenz-Role"
		domain := r.Header.Get(domainHeader)
		role := r.Header.Get(roleHeader)
		at, rt, errMsg, response := "", "", "", []byte("")
		var err error

		if domain == "" || role == "" {
			errMsg = fmt.Sprintf("http headers not set: %s[%s] %s[%s].", domainHeader, domain, roleHeader, role)
		}

		switch idConfig.TokenType {
		case "roletoken":
			if roleTokenCache[domain] == nil {
				errMsg = fmt.Sprintf("domain[%s] was not found in cache.", domain)
			} else if roleTokenCache[domain][role] == nil {
				errMsg = fmt.Sprintf("domain[%s] role[%s] was not found in cache.", domain, role)
			}
		case "accesstoken":
			if accessTokenCache[domain] == nil {
				errMsg = fmt.Sprintf("domain[%s] was not found in cache.", domain)
			} else if accessTokenCache[domain][role] == nil {
				errMsg = fmt.Sprintf("domain[%s] role[%s] was not found in cache.", domain, role)
			}
		case "roletoken+accesstoken":
			if accessTokenCache[domain] == nil || roleTokenCache[domain] == nil {
				errMsg = fmt.Sprintf("domain[%s] was not found in cache.", domain)
			} else if accessTokenCache[domain][role] == nil || roleTokenCache[domain][role] == nil {
				errMsg = fmt.Sprintf("domain[%s] role[%s] was not found in cache.", domain, role)
			}
		}

		if err != nil || len(errMsg) > 0 {
			response, err = json.Marshal(map[string]string{"error": errMsg})
			if err != nil {
				log.Warnf("Error while preparing json response with: message[%s], error[%v]", errMsg, err)
				return
			}
			errMsg = fmt.Sprintf("error writing json response with: %s[%s] %s[%s] error[%s].", domainHeader, domain, roleHeader, role, errMsg)
			log.Warnf(errMsg)
			w.WriteHeader(http.StatusBadRequest)
			io.WriteString(w, string(response))
			return
		}

		switch idConfig.TokenType {
		case "roletoken":
			rt = roleTokenCache[domain][role].Load().(*RoleToken).TokenString
			w.Header().Set(idConfig.RoleAuthHeader, rt)
			response, err = json.Marshal(map[string]string{"roletoken": rt})
		case "accesstoken":
			at = accessTokenCache[domain][role].Load().(*AccessToken).TokenString
			w.Header().Set("Authorization", "bearer "+at)
			response, err = json.Marshal(map[string]string{"accesstoken": at})
		case "roletoken+accesstoken":
			at = accessTokenCache[domain][role].Load().(*AccessToken).TokenString
			rt = roleTokenCache[domain][role].Load().(*RoleToken).TokenString
			w.Header().Set("Authorization", "bearer "+at)
			w.Header().Set(idConfig.RoleAuthHeader, rt)
			response, err = json.Marshal(map[string]string{"accesstoken": at, "roletoken": rt})
		}

		if err != nil {
			log.Warnf("Error while preparing json response with: message[%s], error[%v]", errMsg, err)
			return
		}

		log.Debugf("Returning %s for domain[%s], role[%s]", idConfig.TokenType, domain, role)
		io.WriteString(w, string(response))
	}

	go func() {

		err = backoff.RetryNotify(run, getExponentialBackoff(), notifyOnErr)

		if idConfig.Init {
			if err != nil {
				log.Errorf("Failed to get initial tokens after multiple retries: %s", err.Error())
			}

			log.Infof("Token provider is disabled for init mode: address[%s]", idConfig.TokenServerAddr)

			return
		}

		httpServer := &http.Server{
			Addr:    idConfig.TokenServerAddr,
			Handler: http.HandlerFunc(tokenHandler),
		}

		go func() {

			log.Infof("Starting token provider[%s]", idConfig.TokenServerAddr)

			if err := httpServer.ListenAndServe(); err != nil {
				log.Errorf("Failed to start token provider: %s", err.Error())
			}
		}()

		t := time.NewTicker(idConfig.TokenRefresh)
		defer t.Stop()

		for {

			log.Infof("Refreshing tokens for roles[%v] in %s", idConfig.TargetDomainRoles, idConfig.TokenRefresh)

			select {
			case <-t.C:
				err := backoff.RetryNotify(run, getExponentialBackoff(), notifyOnErr)
				if err != nil {
					log.Errorf("Failed to refresh tokens after multiple retries: %s", err.Error())
				}
			case <-stopChan:
				ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
				httpServer.SetKeepAlivesEnabled(false)
				if err := httpServer.Shutdown(ctx); err != nil {
					log.Errorf("Failed to shutdown token provider: %s", err.Error())
				}
				return
			}
		}
	}()

	return nil
}
