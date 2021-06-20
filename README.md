
# Restrictions

* All custom defined identifier must alphabet-number only.
    - Automatically generated identifier will contain dashes.
* Service Identify Numbers (`ServiceIdent`) must be positive 16-bits integers (`int16`).
    - Packaging into 2 bytes.

# Design Notes

## Services

* Message Switch
    - Service Register
    - Certificate Manager
* Access Gate
    - HTTP server
    - HTTP client
* Content Edge
* Content Fetcher
* HTTP Server

# Build Commands

## Protocal Buffer Stub

```sh
protoc --proto_path=. --go_out=./gen/qbw1grpcgen --go_opt=paths=source_relative message-idl.proto
```

### Service Binary

```sh
go build github.com/qabalwrap/qabalwrap-1/cmd/qabalwrapd
```
