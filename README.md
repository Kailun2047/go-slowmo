# Development

## Install tooling for protobuf and grpc code generation

Install the protoc compiler:

```bash
PB_REL="https://github.com/protocolbuffers/protobuf/releases"
curl -LO $PB_REL/download/v3.12.4/protoc-3.12.4-linux-x86_64.zip
unzip protoc-3.12.4-linux-x86_64.zip -d INSTALLATION_DIR_OF_CHOICE (and add INSTALLATION_DIR_OF_CHOICE/bin to PATH)
```

Install the plugins for used languages:

```bash
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.6
```

```bash
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.5.1
```

```bash
yarn global add @protobuf-ts/plugin@2.11.1
```

## Start containers

### Start dev container

```bash
docker run --name dev --rm --cap-add=BPF --cap-add=SYS_RESOURCE --cap-add=SYS_ADMIN -d -p 5173:5173 -p 50051:50051 go-slowmo-dev:ubuntu2404 sleep 256d
```

### Start envoy proxy

```bash
docker run --rm -d --name=envoy -v "$(pwd)"/config/envoy.yaml:/etc/envoy/envoy.yaml:ro -v "$(pwd)"/envoy_access_log:/etc/envoy/logs \
    --network=host envoyproxy/envoy:dev-3776520dc26dfc0cf5f7ce2af013977d60e4e373 -c /etc/envoy/envoy.yaml -l debug
```

## Build container images

```bash
docker build --platform=linux/amd64 --target slowmo-server -t slowmo-server:[VERSION_TAG] .
```

```bash
docker build --platform=linux/amd64 --target exec-server -t exec-server:[VERSION_TAG] .
```