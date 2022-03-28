FROM docker.io/golang:1-alpine3.15 as builder

WORKDIR /go/src/k8s-athenz-sia

COPY . .

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
