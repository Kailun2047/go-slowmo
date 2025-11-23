FROM ubuntu:noble AS builder

RUN apt-get update
RUN apt-get install -y build-essential
RUN apt-get install -y clang
RUN apt-get install -y git curl unzip

WORKDIR /build

# Install Go.
RUN curl -LO https://go.dev/dl/go1.22.5.linux-amd64.tar.gz
RUN tar -C /usr/local -xzf go1.22.5.linux-amd64.tar.gz
ENV PATH="${PATH}:/usr/local/go/bin"

# Install Node.
RUN curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh | bash
ENV NVM_DIR=/root/.nvm
RUN ["bash", "-c", "source $NVM_DIR/nvm.sh && nvm install 22.16.0"]
ENV PATH="${PATH}:/root/.nvm/versions/node/v22.16.0/bin"
RUN npm install --global yarn

# Build bpftool from source (in case we're building on non-linux host and
# there's no off-the-shelf linux-tools-$(uname -r) to install).
RUN git clone --recurse-submodules https://github.com/libbpf/bpftool.git
RUN apt-get install -y libelf-dev libssl-dev llvm
RUN cd ./bpftool/src && ARCH=x86_64 make install

# Install protobuf and grpc related tooling.
ENV PB_REL="https://github.com/protocolbuffers/protobuf/releases"
RUN curl -LO $PB_REL/download/v3.12.4/protoc-3.12.4-linux-x86_64.zip
RUN unzip protoc-3.12.4-linux-x86_64.zip -d ./protoc
RUN yarn global add @protobuf-ts/plugin@2.11.1
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.6
RUN go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.5.1
ENV PATH="${PATH}:/build/protoc/bin:$(yarn global bin):/root/go/bin"

# Install the target Go versions to support.
ARG go_versions="1.24.10 1.25.4"
RUN for go_version in $go_versions; do \
    go install golang.org/dl/go${go_version}@latest; \
    go${go_version} download; \
  done

# Build the project.
ARG frontend_dev_mode="1"
ARG oauth_client_id=""
ARG proxy_addr="127.0.0.1:50053"
COPY ./ ./go-slowmo
WORKDIR /build/go-slowmo
RUN make libbpf && make go_versions="$go_versions"
WORKDIR /build/go-slowmo/frontend
RUN yarn && VITE_DEV_MODE=$frontend_dev_mode VITE_SLOWMO_CLIENT_ID=$oauth_client_id VITE_SLOWMO_SERVER_HOSTNAME=http://$proxy_addr/api VITE_GO_VERSIONS="$go_versions" yarn build




FROM ubuntu:noble AS slowmo-server

# Add the certificate bundle to enable potential outbound https traffic.
RUN apt-get update && apt-get install -y ca-certificates && update-ca-certificates

COPY --from=builder /root/go/bin/go1* /root/go/bin/
COPY --from=builder /root/sdk /root/sdk
ENV PATH="${PATH}:/root/go/bin"

WORKDIR /app

COPY --from=builder /build/go-slowmo/slowmo-server ./slowmo-server
COPY --from=builder /build/go-slowmo/instrumentor*.o ./
COPY --from=builder /build/go-slowmo/config/cloud-init.yaml ./config/cloud-init.yaml
CMD ["/app/slowmo-server"]




FROM ubuntu:noble AS exec-server

WORKDIR /app

COPY --from=builder /build/go-slowmo/exec-server ./exec-server
RUN groupadd -g 1234 execgroup && useradd -m -u 1234 -g execgroup execuser
USER execuser
CMD ["/app/exec-server"]




FROM node:22-alpine AS slowmo-frontend

WORKDIR /app

COPY --from=builder /build/go-slowmo/frontend/dist ./dist
RUN npm install -D vite
CMD ["npx", "vite", "preview", "--host", "0.0.0.0"]
