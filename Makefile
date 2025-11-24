SHELL = /usr/bin/bash
CC = clang
CFLAGS = -target bpf -O2 -g
DEBUG_GCFLAGS = -gcflags="all=-N -l"
debug = off
go_versions = 1.24.10 1.25.4

instrumentation_dir := ./instrumentation
instrumentor_bpf_src := $(instrumentation_dir)/instrumentor.bpf.c
instrumentor_go_src := $(instrumentation_dir)/*.go
instrumentation_tools_dir := $(instrumentation_dir)/tools
server_dir := ./server
slowmo_server_go_src := $(server_dir)/*.go
middleware_dir := ./middleware
middleware_go_src := $(middleware_dir)/*.go
main_go_src := main.go
instrumentor_bpf_progs := instrumentor*.o
slowmo_server_prog := slowmo-server

exec_dir := ./exec
exec_server_dir := $(exec_dir)/server
exec_server_go_src := $(exec_server_dir)/*.go
exec_main_go_src := $(exec_dir)/$(main_go_src)
exec_server_prog := exec-server

proto_dir := ./proto
slowmo_client_proto_dir := ./frontend/proto
slowmo_proto_file := slowmo.proto
slowmo_proto_def := $(proto_dir)/$(slowmo_proto_file)
slowmo_proto_gen_go := $(proto_dir)/slowmo*.pb.go
slowmo_proto_gen_ts := $(slowmo_client_proto_dir)/slowmo*.ts
exec_proto_file := exec.proto
exec_proto_def := $(proto_dir)/$(exec_proto_file)
exec_proto_gen_go := $(proto_dir)/exec*.pb.go

vmlinux_header := $(instrumentation_dir)/vmlinux.h
instrumentor_header := $(instrumentation_dir)/instrumentor.h

all: proto $(instrumentor_bpf_progs) $(slowmo_server_prog) $(exec_server_prog)

$(vmlinux_header):
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

$(instrumentor_bpf_progs): $(vmlinux_header) $(instrumentor_bpf_src) $(instrumentation_tools_dir)/targets_to_find.json $(instrumentation_tools_dir)/target_finder.go $(instrumentation_tools_dir)/hello.go
	set -e; for go_version in $(go_versions); do \
		pwd=$$(pwd); \
		go$${go_version} build -C $(instrumentation_tools_dir) -o hello hello.go; \
		cd $(instrumentation_tools_dir) && go run target_finder.go; \
		cd $${pwd} && $(CC) $(CFLAGS) -o instrumentor$${go_version}.o -c $(instrumentor_bpf_src); \
	done
	go generate -C $(instrumentation_dir)

$(slowmo_server_prog): $(instrumentor_bpf_progs) $(instrumentor_go_src) $(slowmo_server_go_src) $(main_go_src) $(slowmo_proto_gen_go) $(middleware_go_src)
ifeq ($(debug), on)
	go build $(DEBUG_GCFLAGS) -o $(slowmo_server_prog)
else
	go build -o $(slowmo_server_prog)
endif

$(exec_server_prog): $(exec_server_go_src) $(exec_main_go_src) $(exec_proto_gen_go)
ifeq ($(debug), on)
	go build -C $(exec_dir) $(DEBUG_GCFLAGS) -o ../$(exec_server_prog)
else
	go build -C $(exec_dir) -o ../$(exec_server_prog)
endif

$(slowmo_proto_gen_go): $(slowmo_proto_def)
	protoc --proto_path=$(proto_dir) --go_out=$(proto_dir) --go_opt=paths=source_relative --go-grpc_out=$(proto_dir) --go-grpc_opt=paths=source_relative --experimental_allow_proto3_optional $(slowmo_proto_file)

$(exec_proto_gen_go): $(exec_proto_def)
	protoc --proto_path=$(proto_dir) --go_out=$(proto_dir) --go_opt=paths=source_relative --go-grpc_out=$(proto_dir) --go-grpc_opt=paths=source_relative --experimental_allow_proto3_optional $(exec_proto_file)

$(slowmo_proto_gen_ts): $(slowmo_proto_def)
	mkdir $(slowmo_client_proto_dir)
	npx protoc@32.1.0 -I=$(proto_dir) --ts_out=$(slowmo_client_proto_dir) --experimental_allow_proto3_optional $(slowmo_proto_file)

.PHONY: proto
proto: $(slowmo_proto_gen_go) $(slowmo_proto_gen_ts) $(exec_proto_gen_go)

.PHONY: libbpf
libbpf:
	cd $(instrumentation_dir)/libbpf/src && make install && make install_uapi_headers

$(instrumentation_tools_dir)/hello.go:
	echo -e "//go:build ignore\npackage main\nfunc main() {}" > $(instrumentation_tools_dir)/hello.go

clean:
	rm -r $(slowmo_client_proto_dir)
	rm $(instrumentor_bpf_progs) $(slowmo_server_prog) $(slowmo_proto_gen_go) $(exec_server_prog) $(exec_proto_gen_go) $(vmlinux_header) $(instrumentor_header)