FROM golang:1.27.3-alpine3.24@sha256:f2c872bcee949b7be9c490efd02b48a8a2fbf947cdf533f1c58525ec9d8170fd AS build
# git is build-only: Go's VCS stamping shells out to it so the shipped binary
# reports vcs.revision instead of `mod (devel)`. The runtime stage below does
# not carry it.
RUN apk add --no-cache git
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

# The full checkout (including .git) is required for `-buildvcs=true` to stamp
# the commit: git also compares the worktree, so a partial tree copied file by
# file would report vcs.modified=true. Only the built binary reaches the runner
# stage, and .dockerignore keeps ignored build output out of the context.
COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -buildvcs=true -trimpath -ldflags="-s -w" -o /out/hooshix-gateway ./cmd/gateway

FROM alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
RUN apk add --no-cache ca-certificates curl libcrypto3=3.5.9-r0 libssl3=3.5.9-r0 \
    && addgroup -S -g 10001 hooshix \
    && adduser -S -D -H -u 10001 -G hooshix hooshix

COPY --from=build /out/hooshix-gateway /usr/local/bin/hooshix-gateway

USER 10001:10001
# 8443 is the public TLS/WSS listener; 9090 is the loopback-only
# administrative listener (liveness/readiness/metrics).
EXPOSE 8443 9090
ENTRYPOINT ["/usr/local/bin/hooshix-gateway"]
