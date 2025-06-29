CC = clang
CFLAGS = -target bpf -O2 -g
debug = off

instrumentation_dir := ./instrumentation
server_dir := ./server
instrumentor_bpf_src := $(instrumentation_dir)/instrumentor.bpf.c
instrumentor_go_src := $(instrumentation_dir)/*.go
instrumentor_bpf_prog := instrumentor.o
server_prog := slowmo-server

all: $(instrumentor_bpf_prog) $(server_prog)

# TODO: add libbpf as dependency.
$(instrumentor_bpf_prog): $(instrumentor_bpf_src)
	$(CC) $(CFLAGS) -o $(instrumentor_bpf_prog) -c $(instrumentor_bpf_src)

$(server_prog): $(instrumentor_bpf_prog) $(instrumentor_go_src)
	go generate -C $(instrumentation_dir)
ifeq ($(debug), on)
	go build -gcflags="all=-N -l" -o $(server_prog)
else
	go build -o $(server_prog)
endif

clean:
	rm $(instrumentor_bpf_prog) $(server_prog)