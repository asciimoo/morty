# Morty

[![Build Status](https://travis-ci.org/asciimoo/morty.svg)](https://travis-ci.org/asciimoo/morty)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Docker Pulls](https://img.shields.io/docker/pulls/dalf/morty)](https://hub.docker.com/r/dalf/morty)

Web content sanitizer proxy as a service

Morty rewrites web pages to exclude malicious HTML tags and attributes. It also replaces external resource references to prevent third party information leaks.

The main goal of morty is to provide a result proxy for [searx](https://asciimoo.github.com/searx/), but it can be used as a standalone sanitizer service too.

Features:

 - HTML sanitization
 - Rewrites HTML/CSS external references to locals
 - JavaScript blocking
 - No Cookies forwarded
 - No Referrers
 - No Caching/Etag
 - Supports GET/POST forms and IFrames
 - Optional HMAC URL verifier key to prevent service abuse


## Installation and setup
Requirement: Go version 1.10 or higher.

```
$ go install github.com/asciimoo/morty@latest
$ "$GOPATH/bin/morty" --help
```

### Usage

```
  -debug
        Debug mode (default true)
  -followredirect
        Follow HTTP GET redirect
  -ipv6
        Allow IPv6 HTTP requests (default true)
  -key string
        HMAC url validation key (base64 encoded) - leave blank to disable validation
  -listen string
        Listen address (default "127.0.0.1:3000")
  -proxy string
        Use the specified HTTP proxy (ie: '[user:pass@]hostname:port'). Overrides -socks5, -ipv6.
  -proxyenv
        Use a HTTP proxy as set in the environment (HTTP_PROXY, HTTPS_PROXY and NO_PROXY). Overrides -proxy, -socks5, -ipv6.
  -socks5 string
        Use a SOCKS5 proxy (ie: 'hostname:port'). Overrides -ipv6.
  -timeout uint
        Request timeout (default 5)
  -version
        Show version
```

### Environment variables

Morty can additionally be configured using the following environment variables:
- `MORTY_ADDRESS`: Listen address (default to `127.0.0.1:3000`)
- `MORTY_KEY`: HMAC url validation key (base64 encoded) to prevent direct URL opening. Leave blank to disable validation. Use `openssl rand -base64 33` to generate.
- `DEBUG`: Enable/disable proxy and redirection logs (default to `true`). Set to `false` to disable.

### Docker

```
docker run -e DEBUG=false -e MORTY_ADDRESS=0.0.0.0:3000 dalf/morty
```

```
docker run -e DEBUG=false dalf/morty -listen 0.0.0.0:3000
```


### Test

```
$ cd "$GOPATH/src/github.com/asciimoo/morty"
$ go test
```


### Benchmark

```
$ cd "$GOPATH/src/github.com/asciimoo/morty"
$ go test -benchmem -bench .
```


## Bugs

Bugs or suggestions? Visit the [issue tracker](https://github.com/asciimoo/morty/issues).
