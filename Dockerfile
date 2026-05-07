FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git build-base

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest && \
    CGO_ENABLED=1 xcaddy build \
      --with github.com/josuebrunel/caddy-ja3ja4=. \
      --output /caddy

FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /caddy /usr/local/bin/caddy

RUN addgroup -g 1000 -S caddy && \
    adduser -u 1000 -S caddy -G caddy -h /etc/caddy -s /sbin/nologin && \
    mkdir -p /etc/caddy /var/log/caddy && \
    chown -R caddy:caddy /etc/caddy /var/log/caddy

USER caddy

EXPOSE 80 443

ENTRYPOINT ["/usr/local/bin/caddy"]
CMD ["run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
