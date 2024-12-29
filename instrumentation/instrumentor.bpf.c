//go:build ignore
#include <linux/bpf.h> // TODO: replace with vmlinux.h
#include <bpf/bpf_tracing.h>
#include <stdint.h>
#include <asm/ptrace.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define GO_PARAM1(x) ((x)->rax)
#define GO_PARAM2(x) ((x)->rbx)
#define GO_PARAM3(x) ((x)->rcx)
#define CURR_G_ADDR(x) ((x)->r14)
#define MAX_DELAY_ITERS (1U << 23) // This is currently the max number of iterations permitted by eBPF loop.
#define DELAY_NS 1e9

// TODO: to be compatible with different versions of Go, we should be able to
// retrieve Go runtime internals such as field offsets depending on the target's
// Go version.
// TODO: use unsafe.OffsetOf to acquire field offset instead of hard-coding.
#define G_GOID_OFFSET 152
#define G_M_PTR_OFFSET 48
#define G_PC_OFFSET 64
#define G_STATUS_OFFSET 144
#define M_P_PTR_OFFSET 208
#define P_LOCAL_RUNQ_MAX_LEN 256
#define P_ID_OFFSET 0
#define P_RUNQHEAD_OFFSET 400
#define P_RUNQTAIL_OFFSET 404
#define P_RUNQ_OFFSET 408
#define P_RUNNEXT_OFFSET 2456
#define GET_GOID_ADDR(g_addr) ((char *)(g_addr) + G_GOID_OFFSET)
#define GET_M_ADDR(g_addr) ((char *)(g_addr) + G_M_PTR_OFFSET)
#define GET_PC_ADDR(g_addr) ((char *)(g_addr) + G_PC_OFFSET)
#define GET_STATUS_ADDR(g_addr) ((char *)(g_addr) + G_STATUS_OFFSET)
#define GET_P_ADDR(m_addr) ((char *)(m_addr) + M_P_PTR_OFFSET)
#define GET_P_ID_ADDR(p_addr) ((char *)(p_addr) + P_ID_OFFSET)
#define GET_P_RUNQHEAD_ADDR(p_addr) ((char *)(p_addr) + P_RUNQHEAD_OFFSET)
#define GET_P_RUNQTAIL_ADDR(p_addr) ((char *)(p_addr) + P_RUNQTAIL_OFFSET)
#define GET_P_RUNQ_ADDR(p_addr) ((char *)(p_addr) + P_RUNQ_OFFSET)
#define GET_P_RUNNEXT_ADDR(p_addr) ((char *)(p_addr) + P_RUNNEXT_OFFSET)

int report_runq_status(uint64_t p_ptr_scalar);

// C and Go could have different memory layout (e.g. aligning rule) for the
// "same" struct. uint64_t is used here to ensure consistent encoding/decoding
// of binary data even though event type can be fit into type of smaller size.
const uint64_t EVENT_TYPE_NEWPROC = 0;
const uint64_t EVENT_TYPE_DELAY = 1;
const uint64_t EVENT_TYPE_RUNQ_UPDATE = 2;

// C-equivalent of Go runtime.funcval struct.
struct funcval {
    uint64_t fn;
};

struct newproc_event {
    uint64_t etype;
    uint64_t newproc_pc;
    uint64_t creator_goid;
};

struct delay_event {
    uint64_t etype;
    uint64_t pc;
};

struct runq_entry {
    uint64_t pc;
    uint64_t goid;
    // g status is actually uint32_t but use uint64_t to work around binary
    // SerDe issue caused by data alignment.
    uint64_t status;
};

struct runq_status_event {
    uint64_t etype;
    int64_t procid;
    uint32_t runqhead;
    uint32_t runqtail;
    struct runq_entry local_runq[P_LOCAL_RUNQ_MAX_LEN];
    struct runq_entry runnext;
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
    bpf_probe_read_user(&e->newproc_pc, sizeof(uint64_t), &((struct funcval *)GO_PARAM1(ctx))->fn);
    bpf_probe_read_user(&e->creator_goid, sizeof(uint64_t), GET_GOID_ADDR(CURR_G_ADDR(ctx)));
    bpf_ringbuf_submit(e, 0);
    
    return 0;
}

SEC("uprobe/go_runq_status")
int BPF_UPROBE(go_runq_status) {
    uint32_t runq_i, local_runq_entry_i, local_runq_entry_num;
    char *m_ptr, *p_ptr;

    bpf_probe_read_user(&m_ptr, sizeof(char *), GET_M_ADDR(CURR_G_ADDR(ctx)));
    bpf_probe_read_user(&p_ptr, sizeof(char *), GET_P_ADDR(m_ptr));
    if (!p_ptr) {
        return 1;
    }
    return report_runq_status((uint64_t)(p_ptr));
}

int report_runq_status(uint64_t p_ptr_scalar) {
    struct runq_status_event *e;
    char *local_runq, *runnext_g_ptr, *g_ptr, *p_ptr = (char *)(p_ptr_scalar);
    uint32_t runq_i, local_runq_entry_i, local_runq_entry_num;

    e = bpf_ringbuf_reserve(&instrumentor_event, sizeof(struct runq_status_event), 0);
    if (!e) {
        bpf_printk("bpf_ringbuf_reserve failed in go_runq_status");
        return 1;
    }
    e->etype = EVENT_TYPE_RUNQ_UPDATE;
    bpf_probe_read_user(&e->procid, sizeof(int32_t), GET_P_ID_ADDR(p_ptr));
    bpf_probe_read_user(&e->runqhead, sizeof(uint32_t), GET_P_RUNQHEAD_ADDR(p_ptr));
    bpf_probe_read_user(&e->runqtail, sizeof(uint32_t), GET_P_RUNQTAIL_ADDR(p_ptr));
    local_runq = GET_P_RUNQ_ADDR(p_ptr);
    bpf_probe_read_user(&runnext_g_ptr, sizeof(char *), GET_P_RUNNEXT_ADDR(p_ptr));
    bpf_probe_read_user(&e->runnext.goid, sizeof(uint64_t), GET_GOID_ADDR(runnext_g_ptr));
    bpf_probe_read_user(&e->runnext.pc, sizeof(uint64_t), GET_PC_ADDR(runnext_g_ptr));
    bpf_probe_read_user(&e->runnext.status, sizeof(uint32_t), GET_STATUS_ADDR(runnext_g_ptr));
    bpf_printk("procid: %d, head: %d, tail: %d, runnext.goid: %d, runnext.pc: %x, runnext.status: %d", e->procid, e->runqhead, e->runqtail, e->runnext.goid, e->runnext.pc, e->runnext.status);

    // Store (e->runqhead - e->runqtail) into local variable to prevent the
    // verifier from complaining about potential unbounded memory access.
    local_runq_entry_num = e->runqtail - e->runqhead;
    local_runq_entry_i = e->runqhead % P_LOCAL_RUNQ_MAX_LEN;
    for (runq_i = 0; runq_i < local_runq_entry_num; runq_i++) {
        local_runq_entry_i = (local_runq_entry_i + runq_i) % P_LOCAL_RUNQ_MAX_LEN;
        bpf_probe_read_user(&g_ptr, sizeof(char *), (local_runq + local_runq_entry_i * sizeof(char *)));
        bpf_probe_read_user(&(e->local_runq[local_runq_entry_i].goid), sizeof(uint64_t), GET_GOID_ADDR(g_ptr));
        bpf_probe_read_user(&(e->local_runq[local_runq_entry_i].pc), sizeof(uint64_t), GET_PC_ADDR(g_ptr));
        bpf_probe_read_user(&(e->local_runq[local_runq_entry_i].status), sizeof(uint32_t), GET_STATUS_ADDR(g_ptr));
        bpf_printk("entry %d, goid: %d, pc: %x, status: %d", local_runq_entry_i, e->local_runq[local_runq_entry_i].goid, e->local_runq[local_runq_entry_i].pc, e->local_runq[local_runq_entry_i].status);
        if (local_runq_entry_num > P_LOCAL_RUNQ_MAX_LEN) {
            bpf_printk("distance from runqhead to runqtail is greater than max runq length");
            bpf_ringbuf_discard(e, 0);
            return 1;
        }
    }
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("uprobe/delay")
int BPF_UPROBE(delay) {
    struct delay_event *e;
    uint64_t i, ns, ns_start;
    
    e = bpf_ringbuf_reserve(&instrumentor_event, sizeof(struct delay_event), 0);
    if (!e) {
        bpf_printk("bpf_ringbuf_reserve failed in delay");
        return 1;
    }
    e->etype = EVENT_TYPE_DELAY;
    e->pc = ctx->rip;
    bpf_ringbuf_submit(e, 0);

    ns_start = bpf_ktime_get_ns();
    bpf_for(i, 0, MAX_DELAY_ITERS) {
        ns = bpf_ktime_get_ns();
        if (ns - ns_start >= DELAY_NS) {
            break;
        }
    }
    return 0;
}
