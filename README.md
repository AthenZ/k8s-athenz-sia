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

The opt-in `imds` command serves AWS credentials on the Pod's loopback interface. AWS SDKs can use it by setting `AWS_EC2_METADATA_SERVICE_ENDPOINT=http://127.0.0.1:1338`. It implements the IMDSv2 token request and IAM security credentials paths. The normal SIA identity and token modes are unaffected.

For an AWS Emulator instance whose shared credentials file is mounted in the SIA container:

```sh
athenz-sia imds -source=file -role=zts \
  -credentials-file=/var/run/aws-emulator/9297/emulator_credentials
```

To get temporary credentials for an Athenz authorized AWS role from ZTS:

```sh
athenz-sia imds -source=zts -role=showcaserole -domain=awsshowcase \
  -zts-endpoint=https://athenz-zts-server.athenz:4443/zts/v1 \
  -cert-file=/var/run/athenz/client.cert.pem \
  -key-file=/var/run/athenz/client.key.pem \
  -ca-file=/var/run/athenz/ca.pem
```

Mount the client certificate, key, and CA in the sidecar container. The server listens only on `127.0.0.1:1338` by default, so credentials are available to containers in the same Pod. Both sources are read again when the AWS SDK refreshes credentials; SIA does not write the credentials to its logs or a token file.

The AWS showcase builds a static SIA binary and packages it with `Dockerfile.imds`. This avoids adding a language runtime or another base image to the showcase Pod. The standard SIA Dockerfile remains available for normal deployments.

## Build

Dependencies, including x509-certificate-exporter, are managed through Go modules.

```sh
make
```
