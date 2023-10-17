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

package token

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"time"

	"github.com/AthenZ/k8s-athenz-sia/v3/third_party/log"
)

const (
	DOMAIN_HEADER = "X-Athenz-Domain"
	ROLE_HEADER   = "X-Athenz-Role"
)

func postRoleToken(d *daemon, w http.ResponseWriter, r *http.Request) {
	var err error
	defer func() {
		if r.Context().Err() != nil {
			// skip when request context is done
			return
		}
		if err != nil {
			errMsg := fmt.Sprintf("Error: %s\t%s", err.Error(), http.StatusText(http.StatusInternalServerError))
			http.Error(w, errMsg, http.StatusInternalServerError)
			log.Errorf(errMsg)
		}
	}()

	// parse body
	rtRequest := RoleTokenRequestBody{}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&rtRequest); err != nil {
		return
	}

	// validate body
	domain := rtRequest.Domain
	role := ""
	if rtRequest.Role != nil {
		role = *rtRequest.Role
	}
	if domain == "" {
		err = fmt.Errorf("Invalid value: domain[%s], role[%s]", domain, role)
		return
	}

	// create cache key
	k := CacheKey{Domain: domain, Role: role}
	if rtRequest.ProxyForPrincipal != nil {
		k.ProxyForPrincipal = *rtRequest.ProxyForPrincipal
	}
	if rtRequest.MinExpiry != nil {
		k.MinExpiry = *rtRequest.MinExpiry
	}
	if rtRequest.MaxExpiry != nil {
		k.MaxExpiry = *rtRequest.MaxExpiry
	}
	if k.MinExpiry == 0 {
		k.MinExpiry = d.tokenExpiryInSecond
	}

	// cache lookup (token TTL must >= 1 minute)
	rToken := d.roleTokenCache.Load(k)
	if rToken == nil || time.Unix(rToken.Expiry(), 0).Sub(time.Now()) <= time.Minute {
		log.Debugf("Role token cache miss, attempting to fetch token from Athenz ZTS server: target[%s]", k.String())
		// on cache miss, fetch token from Athenz ZTS server
		rToken, err = fetchRoleToken(d.ztsClient, k)
		if err != nil {
			return
		}
		// update cache
		d.roleTokenCache.Store(k, rToken)
		log.Infof("Role token cache miss, successfully updated role token cache: target[%s]", k.String())
	}

	// check context cancelled
	if r.Context().Err() != nil {
		log.Warnf("Request context cancelled: URL[%s], domain[%s], role[%s], Err[%s]", r.URL.String(), domain, role, r.Context().Err().Error())
		return
	}

	// response
	rtResponse := RoleTokenResponse{
		Token:      rToken.Raw(),
		ExpiryTime: rToken.Expiry(),
	}
	w.Header().Set("Content-type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode(rtResponse)
	return
}

func postAccessToken(d *daemon, w http.ResponseWriter, r *http.Request) {
	var err error
	defer func() {
		if r.Context().Err() != nil {
			// skip when request context is done
			return
		}
		if err != nil {
			errMsg := fmt.Sprintf("Error: %s\t%s", err.Error(), http.StatusText(http.StatusInternalServerError))
			http.Error(w, errMsg, http.StatusInternalServerError)
			log.Errorf(errMsg)
		}
	}()

	// parse body
	atRequest := AccessTokenRequestBody{}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&atRequest); err != nil {
		return
	}

	// validate body
	domain := atRequest.Domain
	role := ""
	if atRequest.Role != nil {
		role = *atRequest.Role
	}
	if domain == "" {
		err = fmt.Errorf("Invalid value: domain[%s], role[%s]", domain, role)
		return
	}

	// create cache key
	k := CacheKey{Domain: domain, Role: role}
	if atRequest.ProxyForPrincipal != nil {
		k.ProxyForPrincipal = *atRequest.ProxyForPrincipal
	}
	if atRequest.Expiry != nil {
		k.MaxExpiry = *atRequest.Expiry
	}
	if k.MaxExpiry == 0 {
		k.MaxExpiry = d.tokenExpiryInSecond
	}

	// cache lookup (token TTL must >= 1 minute)
	aToken := d.accessTokenCache.Load(k)
	if aToken == nil || time.Unix(aToken.Expiry(), 0).Sub(time.Now()) <= time.Minute {
		log.Debugf("Access token cache miss, attempting to fetch token from Athenz ZTS server: target[%s]", k.String())
		// on cache miss, fetch token from Athenz ZTS server
		aToken, err = fetchAccessToken(d.ztsClient, k, d.saService)
		if err != nil {
			return
		}
		// update cache
		d.accessTokenCache.Store(k, aToken)
		log.Infof("Access token cache miss, successfully updated access token cache: target[%s]", k.String())
	}

	// check context cancelled
	if r.Context().Err() != nil {
		log.Warnf("Request context cancelled: URL[%s], domain[%s], role[%s], Err[%s]", r.URL.String(), domain, role, r.Context().Err().Error())
		return
	}

	// response
	atResponse := AccessTokenResponse{
		AccessToken: aToken.Raw(),
		ExpiresIn:   int(time.Unix(aToken.Expiry(), 0).Sub(time.Now()).Seconds()),
		Scope:       nil,
		TokenType:   "Bearer", // hardcoded in the same way as ZTS, https://github.com/AthenZ/athenz/blob/a85f48666763759ee28fda114acc4c8d2cafc28e/servers/zts/src/main/java/com/yahoo/athenz/zts/ZTSImpl.java#L2656C10-L2656C10
	}
	if scope := aToken.(*AccessToken).Scope(); scope != "" {
		atResponse.Scope = &scope // set scope ONLY when non-nil & non-empty, https://github.com/AthenZ/athenz/blob/a85f48666763759ee28fda114acc4c8d2cafc28e/core/zts/src/main/java/com/yahoo/athenz/zts/AccessTokenResponse.java#L21C14-L21C14
	}
	w.Header().Set("Content-type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode(atResponse)
	return
}

func newHandlerFunc(d *daemon, timeout time.Duration) http.Handler {
	// main handler is responsible to monitor whether the request context is cancelled
	mainHandler := func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			// handle panic, reference: https://github.com/golang/go/blob/go1.20.7/src/net/http/server.go#L1851-L1856
			if err := recover(); err != nil && err != http.ErrAbortHandler {
				const size = 64 << 10
				buf := make([]byte, size)
				buf = buf[:runtime.Stack(buf, false)]
				log.Errorf("http: panic serving %v: %v\n%s", r.RemoteAddr, err, buf)

				w.WriteHeader(http.StatusInternalServerError)
			}
		}()

		if d.tokenRESTAPI {
			// sidecar API (server requests' Body is always non-nil)
			if d.tokenType&mROLE_TOKEN != 0 && r.RequestURI == "/roletoken" && r.Method == http.MethodPost {
				postRoleToken(d, w, r)
				return
			}

			if d.tokenType&mACCESS_TOKEN != 0 && r.RequestURI == "/accesstoken" && r.Method == http.MethodPost {
				postAccessToken(d, w, r)
				return
			}
		}

		// API for envoy (all methods and paths)
		domain := r.Header.Get(DOMAIN_HEADER)
		role := r.Header.Get(ROLE_HEADER)

		var errMsg = ""
		var aToken, rToken Token
		if domain == "" || role == "" {
			errMsg = fmt.Sprintf("http headers not set: %s[%s] %s[%s].", DOMAIN_HEADER, domain, ROLE_HEADER, role)
		} else {
			k := CacheKey{Domain: domain, Role: role, MinExpiry: d.tokenExpiryInSecond}
			if d.tokenType&mACCESS_TOKEN != 0 {
				aToken = d.accessTokenCache.Load(k)
				if aToken == nil {
					errMsg = fmt.Sprintf("domain[%s] role[%s] was not found in cache.", domain, role)
				}
			}
			if d.tokenType&mROLE_TOKEN != 0 {
				rToken = d.roleTokenCache.Load(k)
				if rToken == nil {
					errMsg = fmt.Sprintf("domain[%s] role[%s] was not found in cache.", domain, role)
				}
			}
		}

		// check context cancelled
		if r.Context().Err() != nil {
			log.Warnf("Request context cancelled: URL[%s], domain[%s], role[%s], Err[%s]", r.URL.String(), domain, role, r.Context().Err().Error())
			return
		}

		if len(errMsg) > 0 {
			response, err := json.Marshal(map[string]string{"error": errMsg})
			if err != nil {
				log.Warnf("Error while preparing json response with: message[%s], error[%v]", errMsg, err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			errMsg = fmt.Sprintf("Error while handling request with: %s[%s] %s[%s], error[%s]", DOMAIN_HEADER, domain, ROLE_HEADER, role, errMsg)
			log.Warnf(errMsg)
			w.WriteHeader(http.StatusBadRequest)
			io.WriteString(w, string(response))
			return
		}

		resJSON := make(map[string]string, 2)
		if aToken != nil {
			at := aToken.Raw()
			w.Header().Set("Authorization", "bearer "+at)
			resJSON["accesstoken"] = at
		}
		if rToken != nil {
			rt := rToken.Raw()
			w.Header().Set(d.roleAuthHeader, rt)
			resJSON["roletoken"] = rt
		}
		response, err := json.Marshal(resJSON)
		if err != nil {
			log.Warnf("Error while preparing json response with: message[%s], error[%v]", errMsg, err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		log.Debugf("Returning %d for domain[%s], role[%s]", d.tokenType, domain, role)
		io.WriteString(w, string(response))
	}

	// timeout handler
	return http.TimeoutHandler(http.HandlerFunc(mainHandler), timeout, "Handler timeout by token-server-timeout")
}
