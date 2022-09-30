FROM golang:1.18-alpine as builder

WORKDIR /go/src/k8s-athenz-sia

COPY . .

ARG ATHENZ_SIA_VERSION
ARG ATHENZ_SIA_DEFAULT_COUNTRY
ARG ATHENZ_SIA_DEFAULT_PROVINCE
ARG ATHENZ_SIA_DEFAULT_ORGANIZATION
ARG ATHENZ_SIA_DEFAULT_ORGANIZATIONAL_UNIT
ARG ATHENZ_SIA_DEFAULT_ROLE_CERT_EXPIRY_TIME_BUFFER_MINUTES

RUN apk add --no-cache make

RUN make build

FROM docker.io/alpine:3.15

RUN apk --update add ca-certificates

COPY --from=builder /go/bin/athenz-sia /usr/bin/athenz-sia

USER nobody

# --interval=DURATION (default: 30s)
# --timeout=DURATION (default: 30s)
# --start-period=DURATION (default: 0s)
# --retries=N (default: 3)
HEALTHCHECK CMD (stat $SA_TOKEN_FILE) || exit 1

ENTRYPOINT ["/usr/bin/athenz-sia"]
