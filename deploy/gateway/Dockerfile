FROM golang:1.27.0-alpine3.24 AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY cmd/gateway ./cmd/gateway
COPY internal/gateway ./internal/gateway
COPY internal/contractv1 ./internal/contractv1

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/hooshix-gateway ./cmd/gateway

FROM alpine:3.24.1
RUN apk add --no-cache ca-certificates curl \
    && addgroup -S -g 10001 hooshix \
    && adduser -S -D -H -u 10001 -G hooshix hooshix

COPY --from=build /out/hooshix-gateway /usr/local/bin/hooshix-gateway

USER 10001:10001
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/hooshix-gateway"]
