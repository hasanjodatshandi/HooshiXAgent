FROM golang:1.27.2-alpine3.24@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY cmd/gateway ./cmd/gateway
COPY internal/gateway ./internal/gateway
COPY internal/contractv1 ./internal/contractv1
COPY internal/contractv2 ./internal/contractv2

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/hooshix-gateway ./cmd/gateway

FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
RUN apk add --no-cache ca-certificates curl libcrypto3=3.5.9-r0 libssl3=3.5.9-r0 \
    && addgroup -S -g 10001 hooshix \
    && adduser -S -D -H -u 10001 -G hooshix hooshix

COPY --from=build /out/hooshix-gateway /usr/local/bin/hooshix-gateway

USER 10001:10001
# 8443 is the public TLS/WSS listener; 9090 is the loopback-only
# administrative listener (liveness/readiness/metrics).
EXPOSE 8443 9090
ENTRYPOINT ["/usr/local/bin/hooshix-gateway"]
