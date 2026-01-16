FROM golang AS build
WORKDIR /build

COPY . .

RUN go mod tidy \
    && go build -o http-sink main.go


FROM busybox
USER 1000

COPY --chown=1000:1000 --from=build /build/http-sink /usr/local/bin/http-sink

ENTRYPOINT ["http-sink"]
