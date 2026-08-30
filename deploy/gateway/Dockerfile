FROM golang:1.27.0-alpine3.24@sha256:4c9fe60190a2a3350ddc51de80d0224b8a6698d12bdfc999fee45ea9d6c46dbc AS build
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
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/hooshix-gateway"]
