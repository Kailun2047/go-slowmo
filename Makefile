CC = clang
CFLAGS = -target bpf -O2 -g

instrumentation_dir := ./instrumentation
instrumentor_bpf_src := $(instrumentation_dir)/instrumentor.bpf.c
instrumentor_go_src := $(instrumentation_dir)/*.go
instrumentor_bpf_prog := instrumentor.o
instrumentor_go_prog := instrumentor

all: $(instrumentor_bpf_prog) $(instrumentor_go_prog)

# TODO: add libbpf as dependency.
$(instrumentor_bpf_prog): $(instrumentor_bpf_src)
	$(CC) $(CFLAGS) -o $(instrumentor_bpf_prog) -c $(instrumentor_bpf_src)

$(instrumentor_go_prog): $(instrumentor_bpf_prog) $(instrumentor_go_src)
	go build -C $(instrumentation_dir) -o ../$(instrumentor_go_prog)

clean:
	rm $(instrumentor_bpf_prog) $(instrumentor_go_prog)