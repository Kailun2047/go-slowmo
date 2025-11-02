FROM ubuntu:noble AS ubuntu-go

RUN apt-get update
RUN apt-get install -y build-essential
RUN apt-get install -y clang
RUN apt-get install -y git curl unzip

WORKDIR /build

# Install Go.
RUN curl -LO https://go.dev/dl/go1.22.5.linux-amd64.tar.gz
RUN tar -C /usr/local -xzf go1.22.5.linux-amd64.tar.gz
ENV PATH="${PATH}:/usr/local/go/bin"




FROM ubuntu-go AS builder

WORKDIR /build

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

# Build the project.
COPY ./ ./go-slowmo
WORKDIR /build/go-slowmo
RUN make
WORKDIR /build/go-slowmo/frontend
RUN yarn && VITE_SLOWMO_SERVER_HOSTNAME=http://localhost:8080 yarn build




FROM ubuntu:noble AS slowmo-server

COPY --from=ubuntu-go /usr/local/go /usr/local/go
ENV PATH="${PATH}:/usr/local/go/bin"

WORKDIR /app

COPY --from=builder /build/go-slowmo/slowmo-server ./slowmo-server
COPY --from=builder /build/go-slowmo/instrumentor.o ./instrumentor.o
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
