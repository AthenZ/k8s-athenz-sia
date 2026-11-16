# k8s-athenz-sia

[![License: Apache](https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=flat-square)](https://opensource.org/licenses/Apache-2.0)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/AthenZ/k8s-athenz-sia?style=flat-square&label=Github%20version)](https://github.com/AthenZ/k8s-athenz-sia/releases/latest)
[![Docker Image Version (tag latest)](https://img.shields.io/docker/v/athenz/k8s-athenz-sia/latest?style=flat-square&label=Docker%20version)](https://hub.docker.com/r/athenz/k8s-athenz-sia/tags)

## Overview

This repository contains
[Athenz SIA](https://github.com/AthenZ/athenz/blob/master/docs/system_view.md#sia-service-identity-agent-provider)
which is basically aimed to work on Kubernetes environment.

## Usage

```sh
$GOPATH/bin/athenz-sia --help
```

### AWS temporary credentials

`/awstempcred` exchanges SIA's service certificate for IAM Roles Anywhere
credentials. Configure the trust anchor and profile once on the sidecar; callers
specify the IAM role and optionally the session duration.

| Environment variable | Flag |
| --- | --- |
| `AWS_TRUST_ANCHOR_ARN` | `--aws-trust-anchor-arn` |
| `AWS_PROFILE_ARN` | `--aws-profile-arn` |

Both ARNs must belong to the same AWS partition, region and account. The region is
derived from the trust anchor. Certificate/key paths, REST API, HTTP timeout and
TLS settings reuse the existing SIA configuration. AWS/IAM controls which roles
the certificate identity can assume through the profile.

AWS IAM roles are configured independently of Athenz `TARGET_DOMAIN_ROLES`.
This implementation targets trust anchors registered with the CA that directly
issued the workload certificate.

The container image includes the official `aws_signing_helper`. For a standalone
SIA binary, install the [AWS credential helper](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/credential-helper.html)
on `PATH`. SIA fails at startup if AWS support is enabled and the helper is missing.

For an existing workload certificate at the paths below, start an AWS-only sidecar
with the following example ARNs replaced by your trust anchor and profile. Keep
your existing `--provider-service` and identity settings when SIA also provisions
the workload certificate. To also serve Athenz tokens, keep your existing
`--token-type` instead of the empty value.

```sh
_sia_aws_arn_prefix='arn:aws:rolesanywhere:us-east-1:123456789012' &&
athenz-sia \
  --mode refresh \
  --cert /var/run/athenz/service.cert.pem \
  --key /var/run/athenz/service.key.pem \
  --token-type= \
  --token-server-addr 127.0.0.1:8080 \
  --token-server-rest-api \
  --aws-trust-anchor-arn \
    "$_sia_aws_arn_prefix:trust-anchor/11111111-1111-1111-1111-111111111111" \
  --aws-profile-arn \
    "$_sia_aws_arn_prefix:profile/22222222-2222-2222-2222-222222222222"
```

```sh
# Expected: SIA starts the token server on 127.0.0.1:8080
```

From the application container in the same Pod, configure the
[AWS container credential provider](https://docs.aws.amazon.com/sdkref/latest/guide/feature-container-credentials.html).
Replace the example role and bucket with your own:

```sh
_sia_aws_credential_uri=$(
  jq -nr --arg role 'arn:aws:iam::123456789012:role/reader' '
    "http://127.0.0.1:8080/awstempcred?role_arn=" + ($role | @uri)
  '
) &&
AWS_CONTAINER_CREDENTIALS_FULL_URI="$_sia_aws_credential_uri" \
  aws s3 ls s3://example-bucket/ --region us-east-1
```

```sh
# Expected: lists the bucket's objects if the role permits s3:ListBucket
```

The AWS CLI or a compatible SDK calls this URL with GET and refreshes credentials
according to the returned expiration. Set the same environment variable on the
application container to use its default credential provider chain. Existing
credentials with higher precedence, such as access-key environment variables,
must be removed for this provider to be selected.

The path stays fixed; the percent-encoded `role_arn` query parameter selects one
role.
GET returns the container credential fields `AccessKeyId`, `SecretAccessKey`,
`Token` and `Expiration`. An optional `duration_seconds` query parameter controls
the session duration.

For clients that send a JSON request body, POST to the same path:

```sh
curl --fail-with-body --silent --show-error \
  --header 'Content-Type: application/json' \
  --data '{
    "role_arn":"arn:aws:iam::123456789012:role/reader",
    "duration_seconds":3600
  }' \
  http://127.0.0.1:8080/awstempcred |
  jq '
    .AccessKeyId = "<REDACTED>"
    | .SecretAccessKey = "<REDACTED>"
    | .SessionToken = "<REDACTED>"
  '
```

```sh
# Expected response (credential values redacted; expiration is illustrative):
# {
#   "Version": 1,
#   "AccessKeyId": "<REDACTED>",
#   "SecretAccessKey": "<REDACTED>",
#   "SessionToken": "<REDACTED>",
#   "Expiration": "2030-01-01T01:00:00Z"
# }
```

The POST response uses the AWS `credential_process` JSON format, with `SessionToken`
as the session token field. Both methods use the same cache. `duration_seconds`
defaults to 900 and accepts 900–43200 seconds; the IAM role and Roles Anywhere
profile must allow the requested duration. Clients using POST must obtain fresh
credentials before the returned `Expiration`.

Applications using multiple roles should use a separate client or credential
provider for each role.

Each role/duration pair enters the in-memory cache on its first request. Concurrent
requests share one helper invocation. A background worker checks every 30 seconds
and refreshes with 20% of the actual session lifetime remaining, capped at five
minutes; this is independent of `TOKEN_REFRESH_INTERVAL`. On-demand requests also
check expiration.
If refresh fails, cached credentials with more than one minute remaining can still
be returned, with a 30-second wait before retrying AWS; otherwise the endpoint
returns HTTP 503. Requests use `--token-server-timeout` (default 3s) to bound helper
execution. Cancelling one HTTP request does not cancel a fetch shared with other
callers.

Unused entries are evicted after one requested session lifetime, and the cache is
limited to 128 entries. AWS credential values are never written to SIA files or
logs. Responses include `Cache-Control: no-store`. The endpoint shares the token
server's access boundary; use a loopback address for a local sidecar.

## Build

Dependencies, including x509-certificate-exporter, are managed through Go modules.

```sh
make
```
