FROM golang:1.27.1-alpine3.24@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414 AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY cmd/gateway ./cmd/gateway
COPY internal/gateway ./internal/gateway
COPY internal/contractv1 ./internal/contractv1

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/hooshix-gateway ./cmd/gateway

FROM alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b
RUN apk add --no-cache ca-certificates curl libcrypto3=3.5.8-r0 libssl3=3.5.8-r0 \
    && addgroup -S -g 10001 hooshix \
    && adduser -S -D -H -u 10001 -G hooshix hooshix

COPY --from=build /out/hooshix-gateway /usr/local/bin/hooshix-gateway

USER 10001:10001
# 8443 is the public TLS/WSS listener; 9090 is the loopback-only
# administrative listener (liveness/readiness/metrics).
EXPOSE 8443 9090
ENTRYPOINT ["/usr/local/bin/hooshix-gateway"]
