FROM golang:1-buster as builder0

WORKDIR /app-build
COPY . /app-build
RUN go build github.com/qabalwrap/qabalwrap-1/samples/hello-httpd   \
	&& mkdir /app-build/binaries                                    \
	&& mv hello-httpd /app-build/binaries


FROM debian:10

RUN apt-get update                      \
	&& apt-get -y dist-upgrade          \
	&& apt-get -y clean

COPY --from=builder0 /app-build/binaries/*  /opt/qabalwrap-hello-httpd/bin/

CMD ["/opt/qabalwrap-hello-httpd/bin/hello-httpd", "-listen", ":8080", "-message", "HelloWorld"]
