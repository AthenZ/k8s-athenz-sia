package identity

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	authorizerd "github.com/AthenZ/athenz-authorizer/v5"
	"github.com/yahoo/k8s-athenz-identity/pkg/log"
)

func Authorizerd(idConfig *IdentityConfig, stopChan <-chan struct{}) error {

	if idConfig.AuthorizationServerAddr == "" || idConfig.AuthorizationPolicyDomains == "" || idConfig.TokenType == "" {
		log.Infof("Authorizer is disabled with empty options: address[%s], domains[%s], authorizer-type[%s]", idConfig.AuthorizationServerAddr, idConfig.AuthorizationPolicyDomains, idConfig.TokenType)
		return nil
	}

	handler, err := InitIdentityHandler(idConfig)
	if err != nil {
		log.Errorf("Failed to initialize client for authorizer: %s", err.Error())
		return err
	}

	go func() {

		if idConfig.Init {
			log.Infof("Authorizer is disabled for init mode: address[%s]", idConfig.AuthorizationServerAddr)
			return
		}

		authorizerURL, err := url.Parse(idConfig.Endpoint)
		if err != nil {
			log.Errorf("Failed to parse url for authorizer from endpoint[%s]: %s", idConfig.Endpoint, err.Error())
		}
		authorizerClient := &http.Client{
			Transport: handler.Client().Transport,
			Timeout:   handler.Client().Timeout,
		}
		aci, _ := time.ParseDuration(idConfig.AuthorizationCacheInterval)
		daemon, err := authorizerd.New(
			authorizerd.WithAthenzURL(authorizerURL.Host+authorizerURL.Path),
			authorizerd.WithHTTPClient(authorizerClient),
			authorizerd.WithAthenzDomains(strings.Split(idConfig.AuthorizationPolicyDomains, ",")...),
			authorizerd.WithPolicyRefreshPeriod(idConfig.PolicyRefreshInterval),
			authorizerd.WithPubkeyRefreshPeriod(idConfig.PublicKeyRefreshInterval),
			authorizerd.WithCacheExp(aci),
			//authorizerd.WithEnablePubkeyd(),
			authorizerd.WithEnablePolicyd(),
			authorizerd.WithEnableJwkd(),
			authorizerd.WithAccessTokenParam(authorizerd.NewAccessTokenParam(true, false, "", "", false, nil)),
			authorizerd.WithEnableRoleToken(),
			authorizerd.WithRoleAuthHeader(idConfig.RoleAuthHeader),
			//authorizerd.WithEnableRoleCert(),
			//authorizerd.WithRoleCertURIPrefix("athenz://role/"),
		)
		if err != nil {
			log.Errorf("Failed to initialize authorizer: %s", err.Error())
		}
		authzctx := context.Background()
		if err = daemon.Init(authzctx); err != nil {
			log.Errorf("Failed to start authorizer: %s", err.Error())
		}

		authorizerHandler := func(w http.ResponseWriter, r *http.Request) {
			actionHeader := "X-Athenz-Action"
			resourceHeader := "X-Athenz-Resource"
			action := r.Header.Get(actionHeader)
			resource := r.Header.Get(resourceHeader)
			accessTokenHeader := "Authorization"
			at := r.Header.Get(accessTokenHeader)
			rt := r.Header.Get(idConfig.RoleAuthHeader)

			if (at == "" && rt == "") || action == "" || resource == "" {
				log.Infof("Required http headers are not set: %s len(%d), %s len(%d), action[%s], resource[%s]", accessTokenHeader, len(at), idConfig.RoleAuthHeader, len(rt), action, resource)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			principal, err := daemon.Authorize(r, action, resource)
			if err != nil {
				w.WriteHeader(http.StatusUnauthorized)
				log.Infof("Authorization failed with action[%s], resource[%s]: %s", action, resource, err.Error())
				return
			}

			w.WriteHeader(http.StatusAccepted)
			io.WriteString(w, fmt.Sprintf("%v", principal))
		}
		httpServer := &http.Server{
			Addr:    idConfig.AuthorizationServerAddr,
			Handler: http.HandlerFunc(authorizerHandler),
		}

		go func() {
			log.Infof("Starting authorizer: domains[%s]", idConfig.AuthorizationPolicyDomains)

			for err := range daemon.Start(authzctx) {
				log.Errorf("Failed to get initial authorizers after multiple retries: %s", err.Error())
			}
		}()

		go func() {
			log.Infof("Starting authorization server: address[%s]", idConfig.AuthorizationServerAddr)

			if err := httpServer.ListenAndServe(); err != nil {
				log.Errorf("Failed to start authorizer: %s", err.Error())
			}
		}()

		<-stopChan
		ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
		httpServer.SetKeepAlivesEnabled(false)
		if err := httpServer.Shutdown(ctx); err != nil {
			log.Errorf("Failed to shutdown authorizer: %s", err.Error())
		}
	}()

	return nil
}
