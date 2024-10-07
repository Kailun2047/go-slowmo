//go:build ignore
#include <linux/bpf.h> // TODO: replace with vmlinux.h
#include <bpf/bpf_tracing.h>
#include <stdint.h>
#include <asm/ptrace.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define GO_PARAM1(x) ((x)->rax)
#define GO_PARAM2(x) ((x)->rbx)
#define GO_PARAM3(x) ((x)->rcx)
#define DELAY_ITERS (1U << 23) // This is currently the max number of iterations permitted by eBPF loop.

// C and Go could have different memory layout (e.g. aligning rule) for the
// "same" struct. uint64_t is used here to ensure consistent encoding/decoding
// of binary data even though event type can be fit into type of smaller size.
const uint64_t EVENT_TYPE_NEWPROC = 0;
const uint64_t EVENT_TYPE_DELAY = 1;

// C-equivalent of Go runtime.funcval struct.
struct funcval {
    uint64_t fn;
};

struct newproc_event {
    uint64_t etype;
    uint64_t pc;
};

struct delay_event {
    uint64_t etype;
    uint64_t pc;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} instrumentor_event SEC(".maps");

SEC("uprobe/go_newproc")
int BPF_UPROBE(go_newproc) {
    struct newproc_event *e;

    // Retrieve PC value of callee fn and publish to ringbuf.
    e = bpf_ringbuf_reserve(&instrumentor_event, sizeof(struct newproc_event), 0);
    if (!e) {
        bpf_printk("bpf_ringbuf_reserve failed in go_newproc");
        return 1;
    }
    e->etype = EVENT_TYPE_NEWPROC;
    bpf_probe_read_user(&e->pc, sizeof(uint64_t), &((struct funcval *)GO_PARAM1(ctx))->fn);
    bpf_ringbuf_submit(e, 0);
    
    return 0;
}

SEC("uprobe/delay")
int BPF_UPROBE(delay) {
    struct delay_event *e;
    uint64_t i;
    
    e = bpf_ringbuf_reserve(&instrumentor_event, sizeof(struct delay_event), 0);
    if (!e) {
        bpf_printk("bpf_ringbuf_reserve failed in delay");
        return 1;
    }
    e->etype = EVENT_TYPE_DELAY;
    e->pc = ctx->rip;
    bpf_ringbuf_submit(e, 0);

    bpf_for(i, 0, DELAY_ITERS) {
        bpf_ktime_get_ns();
    }
    return 0;
}
