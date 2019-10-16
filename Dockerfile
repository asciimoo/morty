# STEP 1 build executable binary
FROM golang:1.12-alpine as builder

WORKDIR $GOPATH/src/github.com/asciimoo/morty

RUN apk add --no-cache git

COPY . .
RUN go get -d -v
RUN gofmt -l ./
#RUN go vet -v ./...
#RUN go test -v ./...
RUN go build .

# STEP 2 build the image including only the binary
FROM alpine:3.10

EXPOSE 3000

RUN apk --no-cache add ca-certificates \
 && rm -f /var/cache/apk/* \
 && adduser -D -h /usr/local/morty -s /bin/false morty morty

COPY --from=builder /go/src/github.com/asciimoo/morty/morty /usr/local/morty/morty

USER morty

ENV DEBUG=true

ENTRYPOINT ["/usr/local/morty/morty"]
