# Running locally

Build and start all containers:

```bash
docker compose up
```

Then open `http://127.0.0.1:50053` in browser.

# Development

## Build and start development container

Build image for development container (which will have all dev dependencies ready):

```bash
docker build --platform=linux/amd64 --target=builder -t builder:latest .
```

Start the development container:

```bash
docker run --rm -d --name builder --cap-add CAP_SYS_ADMIN --cap-add CAP_BPF --cap-add CAP_SYS_RESOURCE -v ${SHARED_VOLUME_WITH_EXEC_CONTAINER}:/tmp/slowmo-builds builder:latest sleep 256d
```

`SHARED_VOLUME_WITH_EXEC_CONTAINER` is the volume shared with exec container to pass the compiled binary. For example, if the exec container is already built and started from the compose file, then this volume is created by compose and should be named `go-slowmo_slowmo-builds`.