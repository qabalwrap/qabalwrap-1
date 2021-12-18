
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

## Accesses from Message Switch to Services

### HTTP Server

* Start
* Stop
* Certificate change

## Runtime Co-Routines

* Service Routines: Activate and Deactivated by Message Switch via invoke Start() and Stop() methods of service.
* Message Switch Management Routine: Management internal states such as status of access provider, modify service records. Operations in this routine should response as soon as possible.
* Message Switch Maintenance (Fulfill) Routine: Invokes callbacks of services to notify response of request is ready. Operations in this routine may blocked for longer time.

## Runtime Stages

* Setup
* Start
* Run / Operation
* Stop

# Build Commands

## Protocal Buffer Stub

```sh
protoc --proto_path=. --go_out=./gen/qbw1grpcgen --go_opt=paths=source_relative message-idl.proto
```

## Diagnosis RPC Stub

```sh
protoc -I ./ ./diagnosis-idl.proto --go_out=./gen/qbw1diagrpcgen --go_opt=paths=source_relative --go-grpc_out=./gen/qbw1diagrpcgen --go-grpc_opt=paths=source_relative
```

## Service Binary

```sh
go build github.com/qabalwrap/qabalwrap-1/cmd/qabalwrapd
```
