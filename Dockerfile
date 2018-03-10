FROM golang:1.9 as compiler
RUN go get -u github.com/golang/dep/cmd/dep
RUN mkdir -p /go/src/github.com/morvencao/kube-mutating-webhook-tutorial
WORKDIR /go/src/github.com/morvencao/kube-mutating-webhook-tutorial
COPY Gopkg.toml Gopkg.lock *.go ./
RUN dep ensure
RUN CGO_ENABLED=0 go install -a -ldflags '-s' github.com/morvencao/kube-mutating-webhook-tutorial

FROM scratch
COPY --from=compiler /go/bin/kube-mutating-webhook-tutorial .
ENTRYPOINT ["./kube-mutating-webhook-tutorial"]