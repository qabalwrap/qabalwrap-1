FROM golang:1-bullseye as builder0

WORKDIR /app-build
COPY . /app-build
RUN go build github.com/qabalwrap/qabalwrap-1/cmd/qabalwrapd    \
	&& mkdir /app-build/binaries                                \
	&& mv qabalwrapd /app-build/binaries


FROM debian:11

RUN apt-get update                      \
	&& apt-get -y dist-upgrade          \
	&& apt-get -y clean                 \
	&& mkdir -p /opt/qabalwrap-1/etc    \
	&& mkdir -p /opt/qabalwrap-1/var

COPY --from=builder0 /app-build/binaries/*  /opt/qabalwrap-1/bin/

CMD ["/opt/qabalwrap-1/bin/qabalwrapd", "-conf", "/opt/qabalwrap-1/etc/qabalwrap-service.yaml"]
