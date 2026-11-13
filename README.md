# k8s-athenz-sia

[![License: Apache](https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=flat-square)](https://opensource.org/licenses/Apache-2.0)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/AthenZ/k8s-athenz-sia?style=flat-square&label=Github%20version)](https://github.com/AthenZ/k8s-athenz-sia/releases/latest)
[![Docker Image Version (tag latest)](https://img.shields.io/docker/v/athenz/k8s-athenz-sia/latest?style=flat-square&label=Docker%20version)](https://hub.docker.com/r/athenz/k8s-athenz-sia/tags)

## Overview

This repository contains [Athenz SIA](https://github.com/AthenZ/athenz/blob/master/docs/system_view.md#sia-service-identity-agent-provider) which is basically aimed to work on Kubernetes environment.

## Usage

```sh
$GOPATH/bin/athenz-sia --help
```

### AWS credentials through IMDSv2

Set `-mode=refresh -use-imds-server` to run the IMDSv2 server alongside SIA's existing certificate and token services. It listens on the Pod's loopback interface. AWS SDKs can use it with `AWS_EC2_METADATA_SERVICE_ENDPOINT=http://127.0.0.1:1338`. Configure SIA's certificate and key as usual; the ZTS source uses that same identity for mTLS.

Use `-imds-source=file` to expose credentials from a local AWS shared credentials file through SIA's IMDSv2 endpoint. Mount the file in the SIA container; a separate process must provide and rotate its contents. SIA reads the `[default]` profile on each credentials request, including `aws_access_key_id`, `aws_secret_access_key`, and the optional `aws_session_token`.

For example:

```sh
athenz-sia -mode=refresh -cert=/var/run/athenz/client.cert.pem \
  -key=/var/run/athenz/client.key.pem -use-imds-server \
  -imds-source=file -imds-role=localrole \
  -imds-credentials-file=/var/run/aws/credentials
```

For temporary credentials, add `expiration` in RFC 3339 format to the `[default]` profile so the IMDSv2 response reports their actual expiry. This is an optional SIA-specific field alongside the standard AWS credential fields. Without it, SIA reports an expiry one hour after each file read and may serve credentials after their actual expiry.

```ini
[default]
aws_access_key_id = ASIA...
aws_secret_access_key = ...
aws_session_token = ...
expiration = 2030-01-01T00:00:00Z
```

To get temporary credentials for an Athenz authorized AWS role from ZTS:

```sh
athenz-sia -mode=refresh -cert=/var/run/athenz/client.cert.pem \
  -key=/var/run/athenz/client.key.pem \
  -endpoint=https://athenz-zts-server.athenz:4443/zts/v1 \
  -server-ca-cert=/var/run/athenz/ca.pem \
  -use-imds-server -imds-source=zts -imds-role=showcaserole \
  -imds-domain=awsshowcase
```

Mount the certificate, key, and CA in the sidecar container. The server accepts only loopback listen addresses, so credentials are available to containers in the same Pod. Both sources are read again when the AWS SDK refreshes credentials; SIA does not write the credentials to its logs or a token file. The standard `Dockerfile` builds this mode.

## Build

Dependencies, including x509-certificate-exporter, are managed through Go modules.

```sh
make
```
