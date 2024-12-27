FROM docker.io/golang:1-alpine as base

RUN apk add --no-cache make g++ git

WORKDIR /go/src/k8s-athenz-sia

COPY go.mod .
COPY go.sum .

RUN GO111MODULE=on go mod download

FROM base AS builder

COPY . .

ARG ATHENZ_SIA_VERSION=''
RUN ATHENZ_SIA_VERSION="${ATHENZ_SIA_VERSION}" make build
ARG ATHENZ_SIA_DEFAULT_COUNTRY=US

FROM docker.io/alpine:3
LABEL maintainer "cncf-athenz-maintainers@lists.cncf.io"

RUN apk --no-cache add ca-certificates

COPY --from=builder /go/bin/athenz-sia /usr/bin/athenz-sia

USER nobody

ENV KEY_FILE /var/run/athenz/service.key.pem
ENV CERT_FILE /var/run/athenz/service.cert.pem
ENV CA_CERT_FILE /var/run/athenz/ca.cert.pem

# --interval=DURATION (default: 30s)
# --timeout=DURATION (default: 30s)
# --start-period=DURATION (default: 0s)
# --retries=N (default: 3)
HEALTHCHECK CMD (stat $SA_TOKEN_FILE) || exit 1

ENTRYPOINT ["/usr/bin/athenz-sia"]
