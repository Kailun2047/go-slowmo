//go:build ignore
#include <linux/bpf.h> // TODO: replaced with vmlinux.h
#include <bpf/bpf_tracing.h>
#include <stdint.h>
#include "pt_regs.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define GO_PARAM1(x) ((x)->ax)
#define GO_PARAM2(x) ((x)->bx)
#define GO_PARAM3(x) ((x)->cx)

// C-equivalent of Go runtime.funcval struct.
struct funcval {
    uint64_t fn;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} newproc_fn_pc_cnt SEC(".maps");

SEC("uprobe/go_newproc")
int BPF_UPROBE(go_newproc) {
    uint64_t *pc;
    uint64_t *call_cnt;
    uint64_t new_call_cnt;

    // Retrieve PC value of callee fn and publish to ringbuf.
    pc = bpf_ringbuf_reserve(&newproc_fn_pc_cnt, sizeof(pc), 0);
    if (pc != NULL) {
        bpf_probe_read_user(pc, sizeof(uint64_t), &((struct funcval *)GO_PARAM1(ctx))->fn);
        bpf_ringbuf_submit(pc, 0);
    }
    
    return 0;
}
