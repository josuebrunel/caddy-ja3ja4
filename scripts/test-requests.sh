#!/bin/sh
# Sends requests with different TLS/HTTP settings to the compose "caddy" service
# so each produces a distinct fingerprint. Run via `make docker-test`.
set -u

# The site is localhost:8443; keep that name for SNI/Host but connect to the
# caddy container.
URL="https://localhost:8443/"
CURL="curl -sk --connect-to localhost:8443:caddy:8443"

echo "waiting for caddy..."
i=0
until $CURL -A readiness-probe -o /dev/null "$URL" 2>/dev/null; do
  i=$((i + 1))
  [ "$i" -ge 30 ] && { echo "caddy did not come up" >&2; exit 1; }
  sleep 1
done

run() {
  label=$1; shift
  printf '%-22s ' "$label"
  # First two lines of the body are "JA3: ..." and "JA4: ...".
  $CURL "$@" "$URL" | sed -n '1,2p' | tr '\n' ' '
  echo
}

run "HTTP/2, TLS 1.3"   --http2 --tlsv1.3
run "HTTP/1.1, TLS 1.3" --http1.1 --tlsv1.3
run "HTTP/2, TLS 1.2"   --http2 --tlsv1.2 --tls-max 1.2
run "HTTP/1.1, TLS 1.2" --http1.1 --tlsv1.2 --tls-max 1.2
run "custom user agent" -A "my-scanner/1.0"
