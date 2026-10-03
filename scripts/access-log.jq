# Turns Caddy's JSON access log lines into one compact record per request.
# Usage: docker compose logs --no-log-prefix caddy | jq -R -c -f scripts/access-log.jq
# Non-JSON lines and non-access log lines are skipped.
fromjson?
| select((.logger // "") | startswith("http.log.access"))
| {
    time: (.ts | strftime("%H:%M:%S")),
    client: .request.remote_ip,
    proto: .request.proto,
    tls: (.request.tls.version // null),
    ja3: .ja3,
    ja4: .ja4,
    sorted: .ja3_sorted,
    ua: (.request.headers["User-Agent"][0] // null),
    status: .status
  }
