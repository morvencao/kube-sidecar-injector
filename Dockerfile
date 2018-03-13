FROM alpine:latest

ADD kube-mutating-webhook-tutorial /kube-mutating-webhook-tutorial
ENTRYPOINT ["./kube-mutating-webhook-tutorial"]