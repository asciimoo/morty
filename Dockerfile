# STEP 1 build executable binary
FROM golang:alpine as builder

WORKDIR $GOPATH/src/github.com/asciimoo/morty

RUN apk add --no-cache git

COPY . .
RUN go get -d -v
RUN go build .

# STEP 2 build the image including only the binary
FROM alpine:latest

EXPOSE 3000

RUN apk --no-cache add ca-certificates

RUN adduser -D -h /usr/local/morty -s /bin/sh morty morty

USER morty

COPY --from=builder /go/src/github.com/asciimoo/morty/morty /usr/local/morty/morty

ENTRYPOINT ["/usr/local/morty/morty"]
