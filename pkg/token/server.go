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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"time"

	"github.com/AthenZ/k8s-athenz-sia/v3/third_party/log"
	"github.com/google/uuid"
)

const (
	DOMAIN_HEADER = "X-Athenz-Domain"
	ROLE_HEADER   = "X-Athenz-Role"
	roleToken     = "role token"
	accessToken   = "access token"
)

// getKey returns key for the singleflight.Group,
// ensuring that the key used in singleflight is unique is important to prevent collisions.
// Athenz domain naming rule: "[a-zA-Z0-9_][a-zA-Z0-9_-]*")
// Athenz role naming rule: "[a-zA-Z0-9_][a-zA-Z0-9_-]*"
// and therefore delimiter "|" is used to separate domain and role for uniqueness.
func getKey(tokenType, domain, role string) string {
	d := "|" // delimiter; using not allowed character for domain/role
	return tokenType + d + domain + d + role
}

// GroupDoHandledResult contains token and its requestID after singleFlight.group.Do()
// TODO: Maybe shorter name for GroupDoHandledResult
type GroupDoHandledResult struct {
	requestID string
	token     Token
}

// requestTokenToZts sends a request to ZTS server to fetch either role token or access token.
func requestTokenToZts(d *daemon, k CacheKey, tokenName, requestID, domain, role string) (GroupDoHandledResult, error) {
	if tokenName != roleToken && tokenName != accessToken {
		return GroupDoHandledResult{}, fmt.Errorf("Invalid token name: %s", tokenName)
	}

	// TODO: Is this really for cache miss? I don't think so.
	log.Debugf("Attempting to fetch %s due to a cache miss from Athenz ZTS server: target[%s], requestID[%s]", tokenName, k.String(), requestID)

	r, err, shared := d.group.Do(getKey(roleToken, domain, role), func() (interface{}, error) {
		// define variables before request to ZTS
		var fetchedToken Token
		var err error

		// on cache miss, fetch token from Athenz ZTS server
		if tokenName == roleToken {
			fetchedToken, err = fetchRoleToken(d.ztsClient, k)
		} else { // or access token
			fetchedToken, err = fetchAccessToken(d.ztsClient, k, d.saService)
		}

		if err != nil {
			log.Debugf("Failed to fetch %s from Athenz ZTS server after a cache miss: target[%s], requestID[%s]", tokenName, k.String(), requestID)
			return GroupDoHandledResult{requestID: requestID, token: nil}, err
		}

		// update cache
		d.roleTokenCache.Store(k, fetchedToken)
		log.Infof("Successfully updated %s cache after a cache miss: target[%s], requestID[%s]", tokenName, k.String(), requestID)
		return GroupDoHandledResult{requestID: requestID, token: fetchedToken}, nil
	})

	handled := r.(GroupDoHandledResult)
	log.Debugf("requestID: [%s] handledRequestId: [%s] roleToken: [%s]", requestID, handled.requestID, handled.token)

	if shared && handled.requestID != requestID { // if it is shared and not the actual performer:
		if err == nil {
			log.Infof("Successfully updated role token cache by coalescing requests to a leader request: target[%s], leaderRequestID[%s], requestID[%s]", k.String(), handled.requestID, requestID)
		} else {
			log.Debugf("Failed to fetch role token while coalescing requests to a leader request: target[%s], leaderRequestID[%s], requestID[%s], err[%s]", k.String(), handled.requestID, requestID, err)
		}
	}

	return handled, err
}

func postRoleToken(d *daemon, w http.ResponseWriter, r *http.Request) {
	requestID := r.Context().Value(contextKeyRequestID).(string)

	var err error
	defer func() {
		if r.Context().Err() != nil {
			// skip when request context is done
			return
		}
		if err != nil {
			errMsg := fmt.Sprintf("Error: %s requestID[%s]\t%s", err.Error(), requestID, http.StatusText(http.StatusInternalServerError))
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
	// TODO: What does time.Unix(rToken.Expiry(), 0).Sub(time.Now()) <= time.Minute mean?
	// TODO: Gotta write a comment for this, or define a variable beforehand.
	if rToken == nil || time.Unix(rToken.Expiry(), 0).Sub(time.Now()) <= time.Minute {
		res, err := requestTokenToZts(d, k, roleToken, requestID, domain, role)
		if err != nil {
			return
		}
		rToken = res.token
	}

	// check context cancelled
	if r.Context().Err() != nil {
		log.Warnf("Request context cancelled: URL[%s], domain[%s], role[%s], requestID[%s], Err[%s]", r.URL.String(), domain, role, requestID, r.Context().Err().Error())
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
	requestID := r.Context().Value(contextKeyRequestID).(string)

	var err error
	defer func() {
		if r.Context().Err() != nil {
			// skip when request context is done
			return
		}
		if err != nil {
			errMsg := fmt.Sprintf("Error: %s requestID[%s]\t%s", err.Error(), requestID, http.StatusText(http.StatusInternalServerError))
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
	// TODO: What does time.Unix(rToken.Expiry(), 0).Sub(time.Now()) <= time.Minute mean?
	// TODO: Gotta write a comment for this, or define a variable beforehand.
	if aToken == nil || time.Unix(aToken.Expiry(), 0).Sub(time.Now()) <= time.Minute {
		res, err := requestTokenToZts(d, k, accessToken, requestID, domain, role)
		if err != nil {
			return
		}
		aToken = res.token
	}

	// check context cancelled
	if r.Context().Err() != nil {
		log.Warnf("Request context cancelled: URL[%s], domain[%s], role[%s], Err[%s], requestID[%s]", r.URL.String(), domain, role, r.Context().Err().Error(), requestID)
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
		requestID := r.Context().Value(contextKeyRequestID).(string)
		defer func() {
			// handle panic, reference: https://github.com/golang/go/blob/go1.20.7/src/net/http/server.go#L1851-L1856
			if err := recover(); err != nil && err != http.ErrAbortHandler {
				const size = 64 << 10
				buf := make([]byte, size)
				buf = buf[:runtime.Stack(buf, false)]
				log.Errorf("http: panic serving %v: %v requestID[%s]\n%s", r.RemoteAddr, err, requestID, buf)

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

		if !d.useTokenServer {
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, string("404 page not found"))
			return
		}

		// Logic for the token server that attaches tokens to response headers begins here:
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
			log.Warnf("Request context cancelled: URL[%s], domain[%s], role[%s], requestID[%s], Err[%s]", r.URL.String(), domain, role, requestID, r.Context().Err().Error())
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

	// logging && timeout handler
	return withLogging(http.TimeoutHandler(http.HandlerFunc(mainHandler), timeout, "Handler timeout by token-server-timeout"))
}

// contextKey is used to create context key to avoid collision
type contextKey struct {
	name string
}

var contextKeyRequestID = &contextKey{"requestID"}

// withLogging wraps handler with logging and request ID injection
func withLogging(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := uuid.New().String()
		ctx := context.WithValue(r.Context(), contextKeyRequestID, requestID)

		startTime := time.Now()
		log.Infof("Received request: method[%s], endpoint[%s], remoteAddr[%s] requestID[%s]", r.Method, r.RequestURI, r.RemoteAddr, requestID)

		// wrap ResponseWriter to cache status code
		wrappedWriter := newLoggingResponseWriter(w)
		handler.ServeHTTP(wrappedWriter, r.WithContext(ctx))

		latency := time.Since(startTime)
		statusCode := wrappedWriter.statusCode
		log.Infof("Response sent: statusCode[%d], latency[%s], requestID[%s]", statusCode, latency, requestID)
	})
}

// loggingResponseWriter is wrapper for http.ResponseWriter
type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

// WriteHeader calls underlying WriteHeader method
func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.statusCode = code
	lrw.ResponseWriter.WriteHeader(code)
}

func newLoggingResponseWriter(w http.ResponseWriter) *loggingResponseWriter {
	return &loggingResponseWriter{w, http.StatusOK}
}
