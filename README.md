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

## Build

### To update the git submodule from the latest commit (HEAD) hash of the remote repository

```sh
git submodule update --recursive --init --remote
make
```

### To update the git submodule from the remote repository

```sh
git submodule update --recursive --init
make
```
