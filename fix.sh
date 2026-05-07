#!/bin/bash
# fix-imports.sh

# Update go.mod
cat > go.mod << 'EOF'
module github.com/josuebrunel/caddy-ja3ja4

go 1.24

require (
	github.com/caddyserver/caddy/v2 v2.11.2
	github.com/dreadl0ck/ja3 v1.1.0
	github.com/exaring/ja4plus v0.0.0-20240404000000-000000000000
	go.uber.org/zap v1.27.0
)

replace github.com/dreadl0ck/tlsx => github.com/dreadl0ck/tlsx v0.0.0-20210113123933-0c6c8e5f8f8e
EOF

# Update imports in all .go files
find . -name "*.go" -type f -exec sed -i 's|github.com/yourorg/caddy-ja3ja4|github.com/josuebrunel/caddy-ja3ja4|g' {} \;
find . -name "*.go" -type f -exec sed -i 's|github.com/secureworks/ja3|github.com/dreadl0ck/ja3|g' {} \;
find . -name "*.go" -type f -exec sed -i 's|github.com/FoxIO-LLC/ja4|github.com/exaring/ja4plus|g' {} \;

# Fetch dependencies
go mod tidy
