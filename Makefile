.PHONY: submodule-update build test clean
.DEFAULT_GOAL := build

# ifeq ($(GOPATH),)
# 	GOPATH := $(shell pwd)
# endif

# export GOPATH

LDFLAGS :=
ifneq ($(ATHENZ_SIA_VERSION),)
LDFLAGS_ARGS += -X 'github.com/AthenZ/k8s-athenz-sia/v3/pkg/config.VERSION=$(ATHENZ_SIA_VERSION)'
else
LDFLAGS_ARGS += -X 'github.com/AthenZ/k8s-athenz-sia/v3/pkg/config.VERSION=$(shell git rev-parse --short HEAD)'
endif
ifneq ($(ATHENZ_SIA_BUILD_DATE),)
LDFLAGS_ARGS += -X 'github.com/AthenZ/k8s-athenz-sia/v3/pkg/config.BUILD_DATE=$(ATHENZ_SIA_BUILD_DATE)'
else
LDFLAGS_ARGS += -X 'github.com/AthenZ/k8s-athenz-sia/v3/pkg/config.BUILD_DATE=$(shell date '+%Y-%m-%dT%H:%M:%S%Z%z')'
endif
ifneq ($(ATHENZ_SIA_DEFAULT_ENDPOINT),)
LDFLAGS_ARGS += -X 'github.com/AthenZ/k8s-athenz-sia/v3/pkg/config.DEFAULT_ENDPOINT=$(ATHENZ_SIA_DEFAULT_ENDPOINT)'
endif
ifneq ($(ATHENZ_SIA_DEFAULT_DNS_SUFFIX),)
LDFLAGS_ARGS += -X 'github.com/AthenZ/k8s-athenz-sia/v3/pkg/config.DEFAULT_DNS_SUFFIX=$(ATHENZ_SIA_DEFAULT_DNS_SUFFIX)'
endif
ifneq ($(ATHENZ_SIA_DEFAULT_ROLE_CERT_FILENAME_DELIMITER),)
LDFLAGS_ARGS += -X 'github.com/AthenZ/k8s-athenz-sia/v3/pkg/config.DEFAULT_ROLE_CERT_FILENAME_DELIMITER=$(ATHENZ_SIA_DEFAULT_ROLE_CERT_FILENAME_DELIMITER)'
endif
ifneq ($(ATHENZ_SIA_DEFAULT_ROLE_AUTH_HEADER),)
LDFLAGS_ARGS += -X 'github.com/AthenZ/k8s-athenz-sia/v3/pkg/config.DEFAULT_ROLE_AUTH_HEADER=$(ATHENZ_SIA_DEFAULT_ROLE_AUTH_HEADER)'
endif

# TODO: deprecate: ATHENZ_SIA_DEFAULT_COUNTRY, ATHENZ_SIA_DEFAULT_PROVINCE, ATHENZ_SIA_DEFAULT_ORGANIZATION, ATHENZ_SIA_DEFAULT_ORGANIZATIONAL_UNIT
# TODO: add build argument ATHENZ_SIA_DEFAULT_SUBJECT='OU=Athenz' after the deprecation
ifneq ($(ATHENZ_SIA_DEFAULT_COUNTRY),)
LDFLAGS_ARGS += -X 'github.com/AthenZ/k8s-athenz-sia/v3/pkg/config.DEFAULT_COUNTRY=$(ATHENZ_SIA_DEFAULT_COUNTRY)'
endif
ifneq ($(ATHENZ_SIA_DEFAULT_PROVINCE),)
LDFLAGS_ARGS += -X 'github.com/AthenZ/k8s-athenz-sia/v3/pkg/config.DEFAULT_PROVINCE=$(ATHENZ_SIA_DEFAULT_PROVINCE)'
endif
ifneq ($(ATHENZ_SIA_DEFAULT_ORGANIZATION),)
LDFLAGS_ARGS += -X 'github.com/AthenZ/k8s-athenz-sia/v3/pkg/config.DEFAULT_ORGANIZATION=$(ATHENZ_SIA_DEFAULT_ORGANIZATION)'
endif
ifneq ($(ATHENZ_SIA_DEFAULT_ORGANIZATIONAL_UNIT),)
LDFLAGS_ARGS += -X 'github.com/AthenZ/k8s-athenz-sia/v3/pkg/config.DEFAULT_ORGANIZATIONAL_UNIT=$(ATHENZ_SIA_DEFAULT_ORGANIZATIONAL_UNIT)'
endif

ifneq ($(ATHENZ_SIA_DEFAULT_ROLE_CERT_EXPIRY_TIME_BUFFER_MINUTES_RAW),)
LDFLAGS_ARGS += -X 'github.com/AthenZ/k8s-athenz-sia/v3/pkg/config.DEFAULT_ROLE_CERT_EXPIRY_TIME_BUFFER_MINUTES_RAW=$(ATHENZ_SIA_DEFAULT_ROLE_CERT_EXPIRY_TIME_BUFFER_MINUTES_RAW)'
endif
ifneq ($(ATHENZ_SIA_DEFAULT_TOKEN_EXPIRY_RAW),)
LDFLAGS_ARGS += -X 'github.com/AthenZ/k8s-athenz-sia/v3/pkg/config.DEFAULT_TOKEN_EXPIRY_RAW=$(ATHENZ_SIA_DEFAULT_TOKEN_EXPIRY_RAW)'
endif
ifneq ($(ATHENZ_SIA_DEFAULT_INTERMEDIATE_CERT_BUNDLE),)
LDFLAGS_ARGS += -X 'github.com/AthenZ/k8s-athenz-sia/v3/pkg/config.DEFAULT_INTERMEDIATE_CERT_BUNDLE=$(ATHENZ_SIA_DEFAULT_INTERMEDIATE_CERT_BUNDLE)'
endif
ifneq ($(ATHENZ_SIA_DEFAULT_ACCESS_TOKEN_FILENAME_DELIMITER),)
LDFLAGS_ARGS += -X 'github.com/AthenZ/k8s-athenz-sia/v3/pkg/config.DEFAULT_ACCESS_TOKEN_FILENAME_DELIMITER=$(ATHENZ_SIA_DEFAULT_ACCESS_TOKEN_FILENAME_DELIMITER)'
endif
ifneq ($(ATHENZ_SIA_DEFAULT_ROLE_TOKEN_FILENAME_DELIMITER),)
LDFLAGS_ARGS += -X 'github.com/AthenZ/k8s-athenz-sia/v3/pkg/config.DEFAULT_ROLE_TOKEN_FILENAME_DELIMITER=$(ATHENZ_SIA_DEFAULT_ROLE_TOKEN_FILENAME_DELIMITER)'
endif

ifneq ($(LDFLAGS_ARGS),)
LDFLAGS += -ldflags "$(LDFLAGS_ARGS) -linkmode=external"
endif

build: submodule-update
	@echo "Building..."
	CGO_ENABLED=1 GOEXPERIMENT=noswissmap go build $(LDFLAGS) -o $(GOPATH)/bin/athenz-sia cmd/athenz-sia/*.go

test:
	@echo "Testing..."
	GOEXPERIMENT=noswissmap go test -v -failfast -timeout 1m -race -covermode=atomic -coverprofile=coverage.out ./...

lint:
	golangci-lint run -c ./.golangci.yml

upgrade:
	go list -u -m all
	go get -t -u ./...

clean:
	rm -rf $(shell pwd)/bin || true
	chmod -R a+w pkg/ || true
	rm -rf $(shell pwd)/pkg || true

check-license-header:
	# go install github.com/apache/skywalking-eyes/cmd/license-eye@latest
	license-eye -c .licenserc.yaml header check
	# license-eye -c .licenserc.yaml header fix

generate:
	# go install github.com/deepmap/oapi-codegen/cmd/oapi-codegen@latest
	go generate ./...

submodule-update:
	git submodule update --recursive --init

submodule-update-remote:
	git submodule update --recursive --init --remote
