# Install tooling for protobuf and grpc code generation

`apt install -y protobuf-compiler`

`go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.1`

`go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.5.1`

# Starting the Envoy proxy

## Using Docker

`docker run --rm -d --name=envoy -v "$(pwd)"/config/envoy.yaml:/etc/envoy/envoy.yaml:ro -v "$(pwd)"/envoy_access_log:/etc/envoy/logs \
    --network=host envoyproxy/envoy:dev-3776520dc26dfc0cf5f7ce2af013977d60e4e373 -c /etc/envoy/envoy.yaml -l debug`