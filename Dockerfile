# STEP 1: get ca-certificates and an user
FROM alpine as alpine
RUN apk --no-cache add ca-certificates \
    && adduser -D -h /usr/local/morty -s /bin/false -u 10001 morty morty

# STEP 2: build executable binary
FROM golang:1.18-alpine as builder

WORKDIR $GOPATH/src/github.com/asciimoo/morty

RUN apk add --no-cache git

COPY . .
RUN go get -d -v
RUN gofmt -l ./
#RUN go vet -v ./...
#RUN go test -v ./...
RUN CGO_ENABLED=0 go build -ldflags '-extldflags "-static"' -tags timetzdata .

# STEP 3: build the image from scratch
FROM scratch

EXPOSE 3000

COPY --from=alpine /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=alpine /etc/passwd /etc/group /etc/
COPY --from=builder /go/src/github.com/asciimoo/morty/morty /usr/local/morty/morty

USER morty

ENV DEBUG=true

ENTRYPOINT ["/usr/local/morty/morty"]
