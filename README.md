# Starting the Envoy proxy

## Using Docker

`docker run -d --name=envoy -v "$(pwd)"/config/envoy.yaml:/etc/envoy/envoy.yaml:ro -v "$(pwd)"/envoy_access_log:/etc/envoy/logs \
    --network=host envoyproxy/envoy:dev-3776520dc26dfc0cf5f7ce2af013977d60e4e373 -c /etc/envoy/envoy.yaml -l debug`