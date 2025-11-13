## Running locally

Build and start all containers:

```bash
docker compose up
```

Then open `http://127.0.0.1:50053` in browser.

## Development

### Build and start other containerized components

```bash
docker compose up [components_needing_no_development]
```

### Build and start development container

Build image for development container (which will have all dev dependencies ready):

```bash
docker build --platform=linux/amd64 --target=builder -t builder:latest .
```

Start the development container (need to mount `go-slowmo_slowmo-builds` volume created by compose, which is used to share compiled binaries between slowmo-server and exec-server):

```bash
docker run --rm -d --name builder --cap-add CAP_SYS_ADMIN --cap-add CAP_BPF --cap-add CAP_SYS_RESOURCE -v go-slowmo_slowmo-builds:/tmp/slowmo-builds builder:latest sleep 256d
```

Here `go-slowmo_slowmo-builds` is the volume created by compose and should be used to share compiled binary between slowmo-server and exec-server.

Connect the development container to the network created by compose:

```bash
docker network connect go-slowmo_default builder
```