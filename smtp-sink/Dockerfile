FROM golang AS build
WORKDIR /build

RUN go mod init emartech/mail-sink \
    && go get github.com/stone/mail-sink \
    && go build github.com/stone/mail-sink


FROM busybox
USER 1000

COPY --chown=1000:1000 --from=build /build/mail-sink /usr/local/bin/mail-sink

ENTRYPOINT ["mail-sink"]
