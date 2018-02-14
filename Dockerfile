FROM golang:1.8.5-alpine3.6 AS builder

ENV GITHUB_REPO=github.com/hlandau/acme/cmd/acmetool

ENV DEPS="libcap-dev git build-base"

RUN apk --no-cache add $DEPS

WORKDIR /

RUN git config --global http.followRedirects true
RUN go get -v $GITHUB_REPO

WORKDIR /go/src/github.com/hlandau/acme/cmd/acmetool

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o acme .

FROM alpine:3.6
RUN apk --no-cache add ca-certificates

WORKDIR /

COPY --from=builder /go/src/github.com/hlandau/acme/cmd/acmetool/acme .

ENTRYPOINT ["/acme"]
