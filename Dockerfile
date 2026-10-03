FROM golang:1.25-alpine AS builder

# Keep in sync with go.mod. Pinned so image builds are reproducible.
ARG XCADDY_VERSION=v0.4.7
ARG CADDY_VERSION=v2.11.4

RUN apk add --no-cache git

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go install github.com/caddyserver/xcaddy/cmd/xcaddy@${XCADDY_VERSION} && \
    CGO_ENABLED=0 xcaddy build ${CADDY_VERSION} \
      --with github.com/josuebrunel/caddy-ja3ja4=. \
      --output /caddy

FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /caddy /usr/local/bin/caddy

RUN addgroup -g 1000 -S caddy && \
    adduser -u 1000 -S caddy -G caddy -h /etc/caddy -s /sbin/nologin && \
    mkdir -p /etc/caddy /var/log/caddy /data /config && \
    chown -R caddy:caddy /etc/caddy /var/log/caddy /data /config

USER caddy

EXPOSE 80 443 443/udp

ENTRYPOINT ["/usr/local/bin/caddy"]
CMD ["run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
