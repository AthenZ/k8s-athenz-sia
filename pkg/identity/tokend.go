package identity

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/pkg/errors"
	"github.com/yahoo/k8s-athenz-identity/pkg/log"
	"github.com/yahoo/k8s-athenz-identity/pkg/util"
)

type TokenCache interface {
	Update(token Token)
	Load(domain, role string) Token
	Range(func(Token) error) error
}

type LockedTokenCache struct {
	cache map[string]map[string]Token
	lock  sync.RWMutex
}

func (c *LockedTokenCache) Update(t Token) {
	c.lock.Lock()
	defer c.lock.Unlock()
	roleMap := c.cache[t.Domain()]
	if roleMap == nil {
		roleMap = make(map[string]Token)
	}
	roleMap[t.Role()] = t
}

func (c *LockedTokenCache) Load(domain, role string) Token {
	c.lock.RLock()
	defer c.lock.RUnlock()
	roleMap := c.cache[domain]
	return roleMap[role]
}

func (c *LockedTokenCache) Range(f func(Token) error) error {
	c.lock.RLock()
	defer c.lock.RUnlock()
	for _, roleMap := range c.cache {
		for _, token := range roleMap {
			err := f(token)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// Tokend starts the token server and refreshes tokens periodically.
func Tokend(idConfig *IdentityConfig, stopChan <-chan struct{}) (error, <-chan struct{}) {

	if stopChan == nil {
		panic(fmt.Errorf("Tokend: stopChan cannot be empty"))
	}

	if idConfig.TokenServerAddr == "" || idConfig.TargetDomainRoles == "" || idConfig.TokenType == "" {
		log.Infof("Token provider is disabled with empty options: address[%s], roles[%s], token-type[%s]", idConfig.TokenServerAddr, idConfig.TargetDomainRoles, idConfig.TokenType)
		return nil, nil
	}

	var roleTokenCache, accessTokenCache TokenCache
	roleTokenCache = &LockedTokenCache{}
	accessTokenCache = &LockedTokenCache{}

	var keyPem, certPem []byte

	handler, err := InitIdentityHandler(idConfig)
	if err != nil {
		log.Errorf("Failed to initialize client for tokens: %s", err.Error())
		return err, nil
	}

	writeFiles := func() error {

		w := util.NewWriter()

		accessTokenCache.Range(func(t Token) error {
			domain := t.Domain()
			role := t.Raw()
			at := t.Raw()
			log.Infof("[New Access Token] Domain: %s, Role: %s", domain, role)
			outPath := filepath.Join(idConfig.TokenDir, domain+":role."+role+".accesstoken")
			log.Debugf("Saving Access Token[%d bytes] at %s", len(at), outPath)
			if err := w.AddBytes(outPath, 0644, []byte(at)); err != nil {
				return errors.Wrap(err, "unable to save access token")
			}
			return nil
		})
		roleTokenCache.Range(func(t Token) error {
			domain := t.Domain()
			role := t.Raw()
			rt := t.Raw()
			log.Infof("[New Role Token] Domain: %s, Role: %s", domain, role)
			outPath := filepath.Join(idConfig.TokenDir, domain+":role."+role+".roletoken")
			log.Debugf("Saving Role Token[%d bytes] at %s", len(rt), outPath)
			if err := w.AddBytes(outPath, 0644, []byte(rt)); err != nil {
				return errors.Wrap(err, "unable to save role token")
			}
			return nil
		})

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
			roleTokenCache.Update(r)
		}
		for _, a := range accessTokens {
			accessTokenCache.Update(a)
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
		var aToken, rToken Token

		if domain == "" || role == "" {
			errMsg = fmt.Sprintf("http headers not set: %s[%s] %s[%s].", domainHeader, domain, roleHeader, role)
		}

		switch idConfig.TokenType {
		case "roletoken":
			rToken := roleTokenCache.Load(domain, role)
			if rToken == nil {
				errMsg = fmt.Sprintf("domain[%s] role[%s] was not found in cache.", domain, role)
			}
		case "accesstoken":
			aToken := accessTokenCache.Load(domain, role)
			if aToken == nil {
				errMsg = fmt.Sprintf("domain[%s] role[%s] was not found in cache.", domain, role)
			}
		case "roletoken+accesstoken":
			rToken := roleTokenCache.Load(domain, role)
			aToken := accessTokenCache.Load(domain, role)
			if rToken == nil || aToken == nil {
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
			rt = rToken.Raw()
			w.Header().Set(idConfig.RoleAuthHeader, rt)
			response, err = json.Marshal(map[string]string{"roletoken": rt})
		case "accesstoken":
			at = aToken.Raw()
			w.Header().Set("Authorization", "bearer "+at)
			response, err = json.Marshal(map[string]string{"accesstoken": at})
		case "roletoken+accesstoken":
			rt = rToken.Raw()
			at = aToken.Raw()
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

	err = backoff.RetryNotify(run, getExponentialBackoff(), notifyOnErr)
	if err != nil {
		log.Errorf("Failed to get initial tokens after multiple retries: %s", err.Error())
	}

	if idConfig.Init {
		log.Infof("Token provider is disabled for init mode: address[%s]", idConfig.TokenServerAddr)
		return nil, nil
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

	shutdownChan := make(chan struct{}, 1)
	t := time.NewTicker(idConfig.TokenRefresh)
	go func() {
		defer t.Stop()
		defer close(shutdownChan)

		for {
			log.Infof("Refreshing tokens for roles[%v] in %s", idConfig.TargetDomainRoles, idConfig.TokenRefresh)

			select {
			case <-t.C:
				err := backoff.RetryNotify(run, getExponentialBackoff(), notifyOnErr)
				if err != nil {
					log.Errorf("Failed to refresh tokens after multiple retries: %s", err.Error())
				}
			case <-stopChan:
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				httpServer.SetKeepAlivesEnabled(false)
				if err := httpServer.Shutdown(ctx); err != nil {
					log.Errorf("Failed to shutdown token provider: %s", err.Error())
				}
				return
			}
		}
	}()

	return nil, shutdownChan
}
