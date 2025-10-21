CC = clang
CFLAGS = -target bpf -O2 -g
debug = off

instrumentation_dir := ./instrumentation
server_dir := ./server
instrumentor_bpf_src := $(instrumentation_dir)/instrumentor.bpf.c
instrumentor_go_src := $(instrumentation_dir)/*.go
server_go_src := $(server_dir)/*.go
main_go_src := main.go
instrumentor_bpf_prog := instrumentor.o
server_prog := slowmo-server

proto_dir := ./proto
client_proto_dir := ./frontend/proto
proto_file := slowmo.proto
proto_def := $(proto_dir)/$(proto_file)
proto_server := $(proto_dir)/slowmo.pb.go
grpc_server := $(proto_dir)/slowmo_grpc.pb.go
proto_client := $(client_proto_dir)/slowmo.ts
grpc_client := $(client_proto_dir)/slowmo.client.ts
vmlinux_header := $(instrumentation_dir)/vmlinux.h

all: proto $(instrumentor_bpf_prog) $(server_prog)

$(vmlinux_header):
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(vmlinux_header)

$(instrumentor_bpf_src): $(vmlinux_header)

$(instrumentor_bpf_prog): $(instrumentor_bpf_src)
	$(CC) $(CFLAGS) -o $(instrumentor_bpf_prog) -c $(instrumentor_bpf_src)
	go generate -C $(instrumentation_dir)

$(server_prog): $(instrumentor_bpf_prog) $(instrumentor_go_src) $(server_go_src) $(main_go_src) $(proto_server) $(grpc_server)
ifeq ($(debug), on)
	go build -gcflags="all=-N -l" -o $(server_prog)
else
	go build -o $(server_prog)
endif

$(proto_server) $(grpc_server): $(proto_def)
	protoc --proto_path=$(proto_dir) --go_out=$(proto_dir) --go_opt=paths=source_relative --go-grpc_out=$(proto_dir) --go-grpc_opt=paths=source_relative --experimental_allow_proto3_optional $(proto_file)

$(proto_client) $(grpc_client): $(proto_def)
	npx protoc@32.1.0 -I=$(proto_dir) --ts_out=$(client_proto_dir) --experimental_allow_proto3_optional slowmo.proto

.PHONY: proto
proto: $(proto_server) $(grpc_server) $(proto_client) $(grpc_client)

clean:
	rm $(instrumentor_bpf_prog) $(server_prog) $(proto_server) $(grpc_server) $(proto_client) $(grpc_client)