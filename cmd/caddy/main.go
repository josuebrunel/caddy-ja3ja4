//go:build caddy

package main

import (
	caddycmd "github.com/caddyserver/caddy/v2/cmd"
	_ "github.com/caddyserver/caddy/v2/modules/standard"
	_ "github.com/josuebrunel/caddy-ja3ja4"
)

func main() {
	caddycmd.Main()
}
