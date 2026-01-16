FROM golang AS build
WORKDIR /build

COPY . .

RUN go mod tidy \
    && go build -o traffic-gen main.go


FROM busybox

USER 1000

COPY --chown=1000:1000 --from=build /build/traffic-gen /usr/local/bin/traffic-gen

ENTRYPOINT ["traffic-gen"]
