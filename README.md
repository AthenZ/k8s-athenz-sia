# k8s-athenz-sia

## Overview

This repository contains [Athenz SIA](https://github.com/AthenZ/athenz/blob/master/docs/system_view.md#sia-service-identity-agent-provider) which is basically aimed to work on Kubernetes environment.

## Usage

```
$GOPATH/bin/athenz-sia --help
```

## Build

### To update the git submodule from the latest commit (HEAD) hash of the remote repository

```
git submodule update --recursive --init --remote
make
```

### To update the git submodule from the remote repository

```
git submodule update --recursive --init
make
```
