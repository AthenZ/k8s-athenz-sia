Feature: k8s-athenz-sia end-to-end
  In order to validate the built k8s-athenz-sia image against a live Athenz deployment
  As a CI workflow
  I want to verify certificate, token, and protected endpoint integration through BDD scenarios

  Scenario: SIA provisions certificates and token files for the workload
    Given the protected workload is provisioned
    Then the SIA container eventually writes "/var/run/athenz/tls.crt"
    And the SIA container eventually writes "/var/run/athenz/athenz:role.authorization-proxy-clients.cert.pem"
    And the SIA container eventually writes "/var/run/athenz/athenz:role.authorization-proxy-clients.accesstoken"
    And the SIA container eventually writes "/var/run/athenz/athenz:role.authorization-proxy-clients.roletoken"

  Scenario: SIA access token API returns a usable token
    Given the protected workload is provisioned
    When I request an access token for domain "athenz" and role "authorization-proxy-clients"
    Then the access token response should contain a JWT
    And the returned access token should be accepted by the protected endpoint

  Scenario: SIA role token API returns a usable token
    Given the protected workload is provisioned
    When I request a role token for domain "athenz" and role "authorization-proxy-clients"
    Then the role token response should contain a token
    And the returned role token should be accepted by the protected endpoint

  Scenario: File tokens are usable with the protected endpoint
    Given the protected workload is provisioned
    Then the access token file "/var/run/athenz/athenz:role.authorization-proxy-clients.accesstoken" should be accepted by the protected endpoint
    And the role token file "/var/run/athenz/athenz:role.authorization-proxy-clients.roletoken" should be accepted by the protected endpoint