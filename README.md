# Morty

[![Build Status](https://travis-ci.org/asciimoo/morty.svg)](https://travis-ci.org/ascimoo/morty)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

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
$ go get github.com/asciimoo/morty
$ "$GOPATH/bin/morty" --help
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