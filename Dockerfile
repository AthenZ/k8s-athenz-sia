FROM docker.io/golang:1-alpine as builder

WORKDIR /go/src/k8s-athenz-sia

COPY . .

ARG ATHENZ_SIA_VERSION
ARG ATHENZ_SIA_BUILD_DATE
ARG ATHENZ_SIA_DEFAULT_ENDPOINT
ARG ATHENZ_SIA_DEFAULT_DNS_SUFFIX
ARG ATHENZ_SIA_DEFAULT_COUNTRY
ARG ATHENZ_SIA_DEFAULT_PROVINCE
ARG ATHENZ_SIA_DEFAULT_ORGANIZATION
ARG ATHENZ_SIA_DEFAULT_ORGANIZATIONAL_UNIT
ARG ATHENZ_SIA_DEFAULT_ROLE_CERT_EXPIRY_TIME_BUFFER_MINUTES

RUN apk add --no-cache make

RUN make build

FROM docker.io/alpine:3

RUN apk --update add ca-certificates

COPY --from=builder /go/bin/athenz-sia /usr/bin/athenz-sia

USER nobody

ENV KEY_FILE /var/run/athenz/service.key.pem
ENV CERT_FILE /var/run/athenz/service.cert.pem
ENV CA_CERT_FILE /var/run/athenz/ca.cert.pem
ENV LOG_DIR /var/log/athenz-sia
ENV SA_TOKEN_FILE /var/run/secrets/kubernetes.io/bound-serviceaccount/token
ENV ROLECERT_DIR /var/run/athenz/
ENV TOKEN_DIR /var/run/athenz/
ENV TOKEN_SERVER_ADDR :8880
ENV METRICS_SERVER_ADDR :9999

# --interval=DURATION (default: 30s)
# --timeout=DURATION (default: 30s)
# --start-period=DURATION (default: 0s)
# --retries=N (default: 3)
HEALTHCHECK CMD (stat $SA_TOKEN_FILE) || exit 1

ENTRYPOINT ["/usr/bin/athenz-sia"]
