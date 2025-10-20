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
	"errors"
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
)

var (
	ClientError = fmt.Errorf("Client error") // error should be fixed by the client-side, log as warning, response 4xx status code
)

func postRoleToken(ts *tokenService, w http.ResponseWriter, r *http.Request) {
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
			if errors.Is(err, ClientError) {
				log.Warn(errMsg)
			} else {
				log.Warn(errMsg)
			}
		}
	}()

	// parse body
	rtRequest := RoleTokenRequestBody{}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&rtRequest); err != nil {
		err = fmt.Errorf("%w: %w", ClientError, err)
		return
	}

	// validate body
	domain := rtRequest.Domain
	role := ""
	if rtRequest.Role != nil {
		role = *rtRequest.Role
	}
	if domain == "" {
		err = fmt.Errorf("%w: Invalid value: domain[%s], role[%s]", ClientError, domain, role)
		return
	}

	// create cache key
	k := CacheKey{Domain: domain, Role: role}
	if rtRequest.ProxyForPrincipal != nil {
		k.ProxyForPrincipal = *rtRequest.ProxyForPrincipal
	}
	if rtRequest.MinExpiry != nil && *rtRequest.MinExpiry > 0 {
		k.MinExpiry = *rtRequest.MinExpiry
	}
	// To prevent the Role Token's expiration from being shorter than the ZTS server's default value,
	// we will ignore the maxExpiry setting value in the request body.
	// if rtRequest.MaxExpiry != nil && *rtRequest.MaxExpiry > 0{
	// 	k.MaxExpiry = *rtRequest.MaxExpiry
	// }
	if k.MinExpiry == 0 && ts.tokenExpiryInSecond > 0 {
		k.MinExpiry = ts.tokenExpiryInSecond
	}

	// cache lookup (token TTL must >= 1 minute)
	var rToken Token
	k, rToken = ts.roleTokenCache.Search(k)
	// TODO: What does time.Unix(rToken.Expiry(), 0).Sub(time.Now()) <= time.Minute mean?
	// TODO: Gotta write a comment for this, or define a variable beforehand.
	if rToken == nil || time.Unix(rToken.Expiry(), 0).Sub(time.Now()) <= time.Minute {
		res, resErr := ts.requestTokenToZts(k, mROLE_TOKEN, requestID)
		err = resErr // assign error for defer
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

func postAccessToken(ts *tokenService, w http.ResponseWriter, r *http.Request) {
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
			if errors.Is(err, ClientError) {
				log.Warn(errMsg)
			} else {
				log.Error(errMsg)
			}
		}
	}()

	// parse body
	atRequest := AccessTokenRequestBody{}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&atRequest); err != nil {
		err = fmt.Errorf("%w: %w", ClientError, err)
		return
	}

	// validate body
	domain := atRequest.Domain
	role := ""
	if atRequest.Role != nil {
		role = *atRequest.Role
	}
	if domain == "" {
		err = fmt.Errorf("%w: Invalid value: domain[%s], role[%s]", ClientError, domain, role)
		return
	}

	// create cache key
	k := CacheKey{Domain: domain, Role: role}
	if atRequest.ProxyForPrincipal != nil {
		k.ProxyForPrincipal = *atRequest.ProxyForPrincipal
	}
	if atRequest.Expiry != nil && *atRequest.Expiry > 0 {
		k.MaxExpiry = *atRequest.Expiry
	}
	if k.MaxExpiry == 0 && ts.tokenExpiryInSecond > 0 {
		k.MaxExpiry = ts.tokenExpiryInSecond
	}

	// cache lookup (token TTL must >= 1 minute)
	var aToken Token
	k, aToken = ts.accessTokenCache.Search(k)
	// TODO: What does time.Unix(rToken.Expiry(), 0).Sub(time.Now()) <= time.Minute mean?
	// TODO: Gotta write a comment for this, or define a variable beforehand.
	if aToken == nil || time.Unix(aToken.Expiry(), 0).Sub(time.Now()) <= time.Minute {
		res, resErr := ts.requestTokenToZts(k, mACCESS_TOKEN, requestID)
		err = resErr // assign error for defer
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

func newHandlerFunc(ts *tokenService, timeout time.Duration) http.Handler {
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

		if ts.idCfg.TokenServer.RestAPI.Use {
			// sidecar API (server requests' Body is always non-nil)
			if ts.tokenType&mROLE_TOKEN != 0 && r.RequestURI == "/roletoken" && r.Method == http.MethodPost {
				postRoleToken(ts, w, r)
				return
			}

			if ts.tokenType&mACCESS_TOKEN != 0 && r.RequestURI == "/accesstoken" && r.Method == http.MethodPost {
				postAccessToken(ts, w, r)
				return
			}
		}

		if !ts.idCfg.TokenServer.HeaderToken.Use {
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
			// TODO: Since the specifications are not yet decided, the value of WriteFileRequired is undetermined.
			// TODO: Maybe we need to separate the cache keys for RT and AT?
			k := CacheKey{Domain: domain, Role: role, MinExpiry: ts.tokenExpiryInSecond}
			if ts.tokenType&mACCESS_TOKEN != 0 {
				k, aToken = ts.accessTokenCache.Search(k)
				if aToken == nil {
					errMsg = fmt.Sprintf("domain[%s] role[%s] was not found in cache.", domain, role)
				}
			}
			if ts.tokenType&mROLE_TOKEN != 0 {
				k, rToken = ts.roleTokenCache.Search(k)
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
				log.Errorf("Error while preparing json response with: message[%s], error[%v]", errMsg, err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			log.Warn(fmt.Errorf("%w: while handling request with: %s[%s] %s[%s], error[%s]", ClientError, DOMAIN_HEADER, domain, ROLE_HEADER, role, errMsg))
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
			w.Header().Set(ts.idCfg.TokenServer.HeaderToken.RoleAuthHeader, rt)
			resJSON["roletoken"] = rt
		}
		response, err := json.Marshal(resJSON)
		if err != nil {
			log.Errorf("Error while preparing json response with: message[%s], error[%v]", errMsg, err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		log.Debugf("Returning %d for domain[%s], role[%s]", ts.tokenType, domain, role)
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
// TODO: Outputting access logs at the INFO level can result in a massive amount of logs for users with high RPS, potentially causing issues.
// Therefore, we are temporarily modifying the system to not output INFO logs.
// In the future, we need to reconsider the logging policy for these logs.
func withLogging(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := uuid.New().String()
		ctx := context.WithValue(r.Context(), contextKeyRequestID, requestID)

		// startTime := time.Now()
		// log.Infof("Received request: method[%s], endpoint[%s], remoteAddr[%s] requestID[%s]", r.Method, r.RequestURI, r.RemoteAddr, requestID)

		// wrap ResponseWriter to cache status code
		wrappedWriter := newLoggingResponseWriter(w)
		handler.ServeHTTP(wrappedWriter, r.WithContext(ctx))

		// TODO: Since this variable is used only once, would it be better to use it directly?
		// latency := time.Since(startTime)
		// statusCode := wrappedWriter.statusCode
		// log.Infof("Response sent: statusCode[%d], latency[%s], requestID[%s]", statusCode, latency, requestID)
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
