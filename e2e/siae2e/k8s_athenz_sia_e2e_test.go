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

package siae2e

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/cucumber/godog"
	jwt "github.com/golang-jwt/jwt/v5"
)

const (
	defaultNamespace            = "athenz"
	defaultClientDeployment     = "client-deployment"
	defaultProtectedDeployment  = "authzproxy-deployment"
	defaultSIAContainer         = "sia"
	defaultCLIContainer         = "athenz-cli"
	defaultInstanceCertPath     = "/var/run/athenz/tls.crt"
	defaultProtectedEndpointURL = "https://authzproxy.athenz.svc.cluster.local/echoserver"
	defaultTokenServerURL       = "http://127.0.0.1:8180"
	defaultRoleAuthHeader       = "Athenz-Role-Auth"
	defaultProvisionTimeout     = 2 * time.Minute
	defaultCommandTimeout       = 10 * time.Second
	pollInterval                = 3 * time.Second
)

type accessTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

type roleTokenResponse struct {
	Token      string `json:"token"`
	ExpiryTime int64  `json:"expiryTime"`
}

type scenarioState struct {
	namespace           string
	clientDeployment    string
	protectedDeployment string
	siaContainer        string
	cliContainer        string
	protectedEndpoint   string
	tokenServerURL      string
	roleAuthHeader      string
	provisionTimeout    time.Duration
	commandTimeout      time.Duration

	accessToken accessTokenResponse
	roleToken   roleTokenResponse
}

func loadState() scenarioState {
	return scenarioState{
		namespace:           envOrDefault("E2E_NAMESPACE", defaultNamespace),
		clientDeployment:    envOrDefault("E2E_CLIENT_DEPLOYMENT", defaultClientDeployment),
		protectedDeployment: envOrDefaultAny([]string{"E2E_PROTECTED_DEPLOYMENT", "E2E_AUTHZPROXY_DEPLOYMENT"}, defaultProtectedDeployment),
		siaContainer:        envOrDefault("E2E_SIA_CONTAINER", defaultSIAContainer),
		cliContainer:        envOrDefault("E2E_CLI_CONTAINER", defaultCLIContainer),
		protectedEndpoint:   envOrDefaultAny([]string{"E2E_PROTECTED_ENDPOINT_URL", "E2E_PROTECTED_URL", "E2E_AUTHZPROXY_URL"}, defaultProtectedEndpointURL),
		tokenServerURL:      envOrDefault("E2E_TOKEN_SERVER_URL", defaultTokenServerURL),
		roleAuthHeader:      envOrDefault("E2E_ROLE_AUTH_HEADER", defaultRoleAuthHeader),
		provisionTimeout:    durationEnvOrDefault("E2E_PROVISION_TIMEOUT", defaultProvisionTimeout),
		commandTimeout:      durationEnvOrDefault("E2E_COMMAND_TIMEOUT", defaultCommandTimeout),
	}
}

func TestFeatures(t *testing.T) {
	t.Helper()

	suite := godog.TestSuite{
		ScenarioInitializer: InitializeScenario,
		Options: &godog.Options{
			Format:   "pretty",
			Paths:    []string{"."},
			TestingT: t,
		},
	}

	if suite.Run() != 0 {
		t.Fatal("godog suite failed")
	}
}

func InitializeScenario(ctx *godog.ScenarioContext) {
	state := &scenarioState{}

	ctx.Before(func(ctx context.Context, sc *godog.Scenario) (context.Context, error) {
		*state = loadState()
		return ctx, nil
	})

	ctx.Step(`^the protected workload is provisioned$`, state.theProtectedWorkloadIsProvisioned)
	ctx.Step(`^the SIA container eventually writes "([^"]*)"$`, state.theSIAContainerEventuallyWrites)
	ctx.Step(`^I request an access token for domain "([^"]*)" and role "([^"]*)"$`, state.iRequestAnAccessToken)
	ctx.Step(`^I request a role token for domain "([^"]*)" and role "([^"]*)"$`, state.iRequestARoleToken)
	ctx.Step(`^the access token response should contain a JWT$`, state.theAccessTokenResponseShouldContainAJWT)
	ctx.Step(`^the role token response should contain a token$`, state.theRoleTokenResponseShouldContainAToken)
	ctx.Step(`^the returned access token should be accepted by the protected endpoint$`, state.theReturnedAccessTokenShouldBeAccepted)
	ctx.Step(`^the returned role token should be accepted by the protected endpoint$`, state.theReturnedRoleTokenShouldBeAccepted)
	ctx.Step(`^the access token file "([^"]*)" should be accepted by the protected endpoint$`, state.theAccessTokenFileShouldBeAccepted)
	ctx.Step(`^the role token file "([^"]*)" should be accepted by the protected endpoint$`, state.theRoleTokenFileShouldBeAccepted)
}

func (s *scenarioState) theProtectedWorkloadIsProvisioned() error {
	deadline := time.Now().Add(s.provisionTimeout)
	for time.Now().Before(deadline) {
		protectedReady, protectedErr := s.kubectl("get", "deployment", s.protectedDeployment, "-o", `jsonpath={.status.readyReplicas}`)
		clientReady, clientErr := s.kubectl("get", "deployment", s.clientDeployment, "-o", `jsonpath={.status.readyReplicas}`)
		if protectedErr == nil && clientErr == nil && strings.TrimSpace(protectedReady) == "1" && strings.TrimSpace(clientReady) == "1" {
			if _, err := s.execInClientContainer(s.siaContainer, "test -f "+shellQuote(defaultInstanceCertPath)); err == nil {
				return nil
			}
		}
		time.Sleep(pollInterval)
	}
	return fmt.Errorf("protected workload did not become ready within %s", s.provisionTimeout)
}

func (s *scenarioState) theSIAContainerEventuallyWrites(path string) error {
	deadline := time.Now().Add(s.provisionTimeout)
	for time.Now().Before(deadline) {
		if _, err := s.execInClientContainer(s.siaContainer, "test -s "+shellQuote(path)); err == nil {
			return nil
		}
		time.Sleep(pollInterval)
	}
	return fmt.Errorf("timed out waiting for file %s", path)
}

func (s *scenarioState) iRequestAnAccessToken(domain, role string) error {
	output, err := s.requestAccessToken(domain, role)
	if err != nil {
		return err
	}
	var response accessTokenResponse
	if err := json.Unmarshal([]byte(output), &response); err != nil {
		return fmt.Errorf("failed to parse access token response: %w; output=%s", err, output)
	}
	if response.AccessToken == "" {
		return fmt.Errorf("access token is empty; output=%s", output)
	}
	s.accessToken = response
	return nil
}

func (s *scenarioState) iRequestARoleToken(domain, role string) error {
	output, err := s.requestRoleToken(domain, role)
	if err != nil {
		return err
	}
	var response roleTokenResponse
	if err := json.Unmarshal([]byte(output), &response); err != nil {
		return fmt.Errorf("failed to parse role token response: %w; output=%s", err, output)
	}
	if response.Token == "" {
		return fmt.Errorf("role token is empty; output=%s", output)
	}
	s.roleToken = response
	return nil
}

func (s *scenarioState) theAccessTokenResponseShouldContainAJWT() error {
	if s.accessToken.AccessToken == "" {
		return fmt.Errorf("access token is empty")
	}
	parsed, _, err := jwt.NewParser().ParseUnverified(s.accessToken.AccessToken, jwt.MapClaims{})
	if err != nil {
		return fmt.Errorf("failed to parse access token JWT: %w", err)
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok || claims["exp"] == nil {
		return fmt.Errorf("access token missing exp claim")
	}
	return nil
}

func (s *scenarioState) theRoleTokenResponseShouldContainAToken() error {
	if s.roleToken.Token == "" {
		return fmt.Errorf("role token is empty")
	}
	if !strings.Contains(s.roleToken.Token, "v=Z1;") {
		return fmt.Errorf("role token does not look like an Athenz role token")
	}
	return nil
}

func (s *scenarioState) theReturnedAccessTokenShouldBeAccepted() error {
	return s.expectAuthorized("Authorization: Bearer " + s.accessToken.AccessToken)
}

func (s *scenarioState) theReturnedRoleTokenShouldBeAccepted() error {
	return s.expectAuthorized(s.roleAuthHeader + ": " + s.roleToken.Token)
}

func (s *scenarioState) theAccessTokenFileShouldBeAccepted(path string) error {
	token, err := s.readFileInContainer(path)
	if err != nil {
		return err
	}
	return s.expectAuthorized("Authorization: Bearer " + token)
}

func (s *scenarioState) theRoleTokenFileShouldBeAccepted(path string) error {
	token, err := s.readFileInContainer(path)
	if err != nil {
		return err
	}
	return s.expectAuthorized(s.roleAuthHeader + ": " + token)
}

func (s scenarioState) readFileInContainer(path string) (string, error) {
	output, err := s.execInClientContainer(s.siaContainer, "cat "+shellQuote(path))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(output), nil
}

func (s scenarioState) requestAccessToken(domain, role string) (string, error) {
	body := fmt.Sprintf(`{"domain":"%s","role":"%s"}`, domain, role)
	return s.execInClientContainer(s.cliContainer, "curl -sSk -X POST -H 'Content-Type: application/json' --data "+shellQuote(body)+" "+shellQuote(strings.TrimRight(s.tokenServerURL, "/")+"/accesstoken"))
}

func (s scenarioState) requestRoleToken(domain, role string) (string, error) {
	body := fmt.Sprintf(`{"domain":"%s","role":"%s"}`, domain, role)
	return s.execInClientContainer(s.cliContainer, "curl -sSk -X POST -H 'Content-Type: application/json' --data "+shellQuote(body)+" "+shellQuote(strings.TrimRight(s.tokenServerURL, "/")+"/roletoken"))
}

func (s scenarioState) expectAuthorized(header string) error {
	command := "curl -sSk -o /tmp/protected-endpoint-response -w '%{http_code}' -H " + shellQuote(header) + " " + shellQuote(s.protectedEndpoint)
	status, err := s.execInClientContainer(s.cliContainer, command)
	if err != nil {
		return err
	}
	if strings.TrimSpace(status) != "200" {
		body, _ := s.execInClientContainer(s.cliContainer, "cat /tmp/protected-endpoint-response || true")
		return fmt.Errorf("expected protected endpoint 200, got %s: %s", strings.TrimSpace(status), strings.TrimSpace(body))
	}
	return nil
}

func (s scenarioState) kubectl(args ...string) (string, error) {
	base := []string{"-n", s.namespace}
	base = append(base, args...)
	return s.runCommand("kubectl", base...)
}

func (s scenarioState) execInClientContainer(container, shell string) (string, error) {
	args := []string{"-n", s.namespace, "exec", "deployment/" + s.clientDeployment, "-c", container, "--", "sh", "-c", shell}
	return s.runCommand("kubectl", args...)
}

func (s scenarioState) runCommand(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.commandTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = os.Environ()
	output, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return "", fmt.Errorf("command timed out after %s: %s %s\n%s", s.commandTimeout, name, strings.Join(args, " "), strings.TrimSpace(string(output)))
	}
	if err != nil {
		return "", fmt.Errorf("command failed: %s %s: %w\n%s", name, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return strings.TrimSpace(string(output)), nil
}

func envOrDefault(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func envOrDefaultAny(keys []string, fallback string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(os.Getenv(key)); value != "" {
			return value
		}
	}
	return fallback
}

func durationEnvOrDefault(key string, fallback time.Duration) time.Duration {
	if raw := strings.TrimSpace(os.Getenv(key)); raw != "" {
		if parsed, err := time.ParseDuration(raw); err == nil {
			return parsed
		}
	}
	return fallback
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'"
}
