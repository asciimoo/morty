# Morty

Web content sanitizer proxy as a service

Morty rewrites web pages to exclude malicious HTML tags and CSS/HTML attributes. It also replaces external resource references to prevent third party information leaks.


other features:

 - GET/POST form support
 - Optional HMAC URL verifier key to prevent service abuse


## Installation and setup

```
$ go get github.com/asciimoo/morty
$ "$GOPATH/bin/morty" --help
```


## Bugs

Bugs or suggestions? Visit the [issue tracker](https://github.com/asciimoo/morty/issues).
