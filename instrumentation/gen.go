package instrumentation

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux instrumentor instrumentor.bpf.c
