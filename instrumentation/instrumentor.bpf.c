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
#define CURR_PC(x) ((x)->rip)
#define CURR_STACK_TOP(x) ((char *)((x)->rsp))
#define MAX_DELAY_ITERS (1U << 23) // This is currently the max number of iterations permitted by eBPF loop.
#define DELAY_NS 1e9

// TODO: to be compatible with different versions of Go, we should be able to
// retrieve Go runtime internals such as field offsets depending on the target's
// Go version.
#define G_GOID_OFFSET 152
#define G_M_PTR_OFFSET 48
#define G_PC_OFFSET 64
#define G_STATUS_OFFSET 144
#define G_SCHEDLINK_OFFSET 160
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
#define GET_SCHEDLINK_ADDR(g_addr) ((char *)(g_addr) + G_SCHEDLINK_OFFSET)
#define GET_P_ADDR(m_addr) ((char *)(m_addr) + M_P_PTR_OFFSET)
#define GET_P_ID_ADDR(p_addr) ((char *)(p_addr) + P_ID_OFFSET)
#define GET_P_RUNQHEAD_ADDR(p_addr) ((char *)(p_addr) + P_RUNQHEAD_OFFSET)
#define GET_P_RUNQTAIL_ADDR(p_addr) ((char *)(p_addr) + P_RUNQTAIL_OFFSET)
#define GET_P_RUNQ_ADDR(p_addr) ((char *)(p_addr) + P_RUNQ_OFFSET)
#define GET_P_RUNNEXT_ADDR(p_addr) ((char *)(p_addr) + P_RUNNEXT_OFFSET)

int report_local_runq_status(uint64_t p_ptr_scalar, struct pt_regs *ctx);

// C and Go could have different memory layout (e.g. aligning rule) for the
// "same" struct. uint64_t is used here to ensure consistent encoding/decoding
// of binary data even though event type can be fit into type of smaller size.
const uint64_t EVENT_TYPE_NEWPROC = 0;
const uint64_t EVENT_TYPE_DELAY = 1;
const uint64_t EVENT_TYPE_RUNQ_STATUS = 2;
const uint64_t EVENT_TYPE_RUNQ_STEAL = 3;
const uint64_t EVENT_TYPE_EXECUTE = 4;
const uint64_t EVENT_TYPE_GLOBRUNQ_STATUS = 5;

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
    // A zero PC indicate an empty entry.
    uint64_t pc;
    uint64_t goid;
    // g status is actually uint32_t but use uint64_t to work around binary
    // SerDe issue caused by data alignment.
    uint64_t status;
};

struct runq_status_event {
    uint64_t etype;
    int64_t procid;
    uint64_t pc;
    uint64_t callerpc;
    uint64_t runqhead;
    uint64_t runqtail;
    // The index of the reported runq entry. When runq_entry_idx = runqtail, it
    // indicates the runq_entry field holds the content of runnext, and the
    // userspace can take it as the last event of the reported runq.
    uint64_t runq_entry_idx;
    struct runq_entry runq_entry;
};

struct runq_steal_event {
    uint64_t etype;
    int64_t stealing_procid;
    int64_t stolen_procid;
};

struct execute_event {
    uint64_t etype;
    int64_t procid;
    uint64_t goid;
    uint64_t gopc;
    uint64_t pc;
    uint64_t callerpc;
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

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, uint64_t);
    __type(value, uint64_t);
    __uint(max_entries, 8); // TODO: use GOMAXPROCS
} runq_stealing SEC(".maps");

SEC("uprobe/go_runqsteal")
int BPF_UPROBE(go_runqsteal) {
    int result;
    struct runq_steal_event *e;
    uint64_t stealing_p_ptr, stolen_p_ptr;

    stealing_p_ptr = (uint64_t)(GO_PARAM1(ctx));
    stolen_p_ptr = (uint64_t)(GO_PARAM2(ctx));
    if ((result = bpf_map_update_elem(&runq_stealing, &stealing_p_ptr, &stolen_p_ptr, BPF_ANY)) != 0) {
        bpf_printk("cannot update runq_stealing entry with key %x", stealing_p_ptr);
        return 1;
    }

    e = bpf_ringbuf_reserve(&instrumentor_event, sizeof(struct runq_steal_event), 0);
    if (!e) {
        bpf_printk("bpf_ringbuf_reserve failed in go_runqsteal");
        return 1;
    }
    e->etype = EVENT_TYPE_RUNQ_STEAL;
    bpf_probe_read_user(&e->stealing_procid, sizeof(int32_t), GET_P_ID_ADDR(stealing_p_ptr));
    bpf_probe_read_user(&e->stolen_procid, sizeof(int32_t), GET_P_ID_ADDR(stolen_p_ptr));
    bpf_ringbuf_submit(e, 0);

    return 0;
}

SEC("uprobe/go_execute")
int BPF_UPROBE(go_execute) {
    struct execute_event *e;
    char *m_ptr, *p_ptr, *g_ptr;

    e = bpf_ringbuf_reserve(&instrumentor_event, sizeof(struct execute_event), 0);
    if (!e) {
        bpf_printk("bpf_ringbuf_reserve failed in go_execute");
        return 1;
    }
    e->etype = EVENT_TYPE_EXECUTE;
    bpf_probe_read_user(&m_ptr, sizeof(char *), GET_M_ADDR(CURR_G_ADDR(ctx)));
    bpf_probe_read_user(&p_ptr, sizeof(char *), GET_P_ADDR(m_ptr));
    bpf_probe_read_user(&e->procid, sizeof(int32_t), GET_P_ID_ADDR(p_ptr));
    bpf_probe_read_user(&e->gopc, sizeof(char *), GET_PC_ADDR(GO_PARAM1(ctx)));
    bpf_probe_read_user(&e->goid, sizeof(char *), GET_GOID_ADDR(GO_PARAM1(ctx)));
    e->pc = CURR_PC(ctx);
    bpf_probe_read_user(&e->callerpc, sizeof(uint64_t), CURR_STACK_TOP(ctx));
    bpf_ringbuf_submit(e, 0);

    return 0;
}

SEC("uprobe/go_runqsteal_ret_runq_status")
int BPF_UPROBE(go_runqsteal_ret_runq_status) {
    int result;
    char *m_ptr;
    uint64_t stealing_p_ptr, *stolen_p_ptr_ptr;

    bpf_probe_read_user(&m_ptr, sizeof(char *), GET_M_ADDR(CURR_G_ADDR(ctx)));
    bpf_probe_read_user(&stealing_p_ptr, sizeof(uint64_t), GET_P_ADDR(m_ptr));

    // Retrieve the pointer to stolen processor.
    stolen_p_ptr_ptr = bpf_map_lookup_elem(&runq_stealing, &stealing_p_ptr);
    if (!stolen_p_ptr_ptr) {
        bpf_printk("cannot retrieve stolen processor pointer with stealing processor pointer %x", stealing_p_ptr);
        return 1;
    }

    // Report runq status of both stealing processor and stolen processor.
    result = report_local_runq_status(stealing_p_ptr, ctx);
    if (result) {
        return result;
    }
    result = report_local_runq_status(*stolen_p_ptr_ptr, ctx);
    return result;
}

SEC("uprobe/go_runtime_func_ret_runq_status")
int BPF_UPROBE(go_runtime_func_ret_runq_status) {
    uint32_t runq_i, local_runq_entry_i;
    char *m_ptr, *p_ptr;

    bpf_probe_read_user(&m_ptr, sizeof(char *), GET_M_ADDR(CURR_G_ADDR(ctx)));
    bpf_probe_read_user(&p_ptr, sizeof(char *), GET_P_ADDR(m_ptr));
    // BCC treats p_ptr as scalar (because it is calculated by adding scalar to
    // memory reference) so we need to make report_local_runq_status accept p's
    // address as scalar value and cast p_ptr.
    return report_local_runq_status((uint64_t)(p_ptr), ctx);
}

int report_local_runq_status(uint64_t p_ptr_scalar, struct pt_regs *ctx) {
    struct runq_status_event *e;
    char *local_runq, *runnext_g_ptr, *g_ptr, *p_ptr = (char *)(p_ptr_scalar);
    uint32_t runqhead, runqtail;
    uint64_t runq_i;
    uint64_t pc, callerpc;
    int32_t procid;

    pc = CURR_PC(ctx);
    bpf_probe_read_user(&callerpc, sizeof(uint64_t), CURR_STACK_TOP(ctx));
    bpf_probe_read_user(&procid, sizeof(int32_t), GET_P_ID_ADDR(p_ptr));
    bpf_probe_read_user(&runqhead, sizeof(uint32_t), GET_P_RUNQHEAD_ADDR(p_ptr));
    bpf_probe_read_user(&runqtail, sizeof(uint32_t), GET_P_RUNQTAIL_ADDR(p_ptr));
    local_runq = GET_P_RUNQ_ADDR(p_ptr);
    bpf_probe_read_user(&runnext_g_ptr, sizeof(char *), GET_P_RUNNEXT_ADDR(p_ptr));

    bpf_for(runq_i, runqhead, runqtail + 1) {
        e = bpf_ringbuf_reserve(&instrumentor_event, sizeof(struct runq_status_event), 0);
        if (!e) {
            bpf_printk("bpf_ringbuf_reserve failed for local runq entry in go_runtime_func_ret_runq_status");
            return 1;
        }
        e->etype = EVENT_TYPE_RUNQ_STATUS;
        e->pc = pc;
        e->runq_entry_idx = runq_i;
        e->callerpc = callerpc;
        e->procid = procid;
        e->runqhead = runqhead;
        e->runqtail = runqtail;
        if (runq_i == runqtail) {
            g_ptr = runnext_g_ptr;
        } else {
            bpf_probe_read_user(&g_ptr, sizeof(char *), (local_runq + (runq_i % P_LOCAL_RUNQ_MAX_LEN) * sizeof(char *)));
        }
        if (!g_ptr) {
            e->runq_entry.pc = 0;
        } else {
            bpf_probe_read_user(&(e->runq_entry.goid), sizeof(uint64_t), GET_GOID_ADDR(g_ptr));
            bpf_probe_read_user(&(e->runq_entry.pc), sizeof(uint64_t), GET_PC_ADDR(g_ptr));
            bpf_probe_read_user(&(e->runq_entry.status), sizeof(uint32_t), GET_STATUS_ADDR(g_ptr));
        }
        bpf_ringbuf_submit(e, 0);
    }
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

// The compiler doesn't know runtime_sched_addr is assigned in userspace. Use
// "volatile" to avoid having runtime_sched_addr treated as an ununsed variable
// and optimized away by compiler.
volatile const __u64 runtime_sched_addr;

#define SCHED_RUNQ_HEAD_OFFSET 104
#define SCHED_RUNQ_SIZE_OFFSET 120
#define SCHED_GET_RUNQ_HEAD_ADDR(sched_addr) ((char *)(sched_addr) + SCHED_RUNQ_HEAD_OFFSET)
#define SCHED_GET_RUNQ_SIZE_ADDR(sched_addr) ((char *)(sched_addr) + SCHED_RUNQ_SIZE_OFFSET)

struct globrunq_status_event {
    uint64_t etype;
    uint64_t pc;
    uint64_t callerpc;
    // The globrunq is a linked structure instead of a fixed-cap array (as local
    // runq is), but we have access to its size. So the userspace knows the
    // event marks the end of globrunq when runq_entry_idx = size - 1.
    int64_t size;
    uint64_t runq_entry_idx;
    struct runq_entry runq_entry;
};

SEC("uprobe/globrunq_status")
int BPF_UPROBE(globrunq_status) {
    char *g_ptr;
    uint64_t pc, callerpc;
    int64_t runq_size;
    uint64_t runq_i;
    struct globrunq_status_event *e;

    pc = CURR_PC(ctx);
    bpf_probe_read_user(&callerpc, sizeof(uint64_t), CURR_STACK_TOP(ctx));
    bpf_probe_read_user(&g_ptr, sizeof(char *), SCHED_GET_RUNQ_HEAD_ADDR(runtime_sched_addr));
    bpf_probe_read_user(&runq_size, sizeof(int32_t), SCHED_GET_RUNQ_SIZE_ADDR(runtime_sched_addr));

    bpf_for(runq_i, 0, runq_size) {
        e = bpf_ringbuf_reserve(&instrumentor_event, sizeof(struct globrunq_status_event), 0);
        if (!e) {
            bpf_printk("bpf_ringbuf_reserve failed in globrunq_status");
            return 1;
        }
        e->etype = EVENT_TYPE_GLOBRUNQ_STATUS;
        e->pc = pc;
        e->callerpc = callerpc;
        e->size = runq_size;
        e->runq_entry_idx = runq_i;
        bpf_probe_read_user(&(e->runq_entry.goid), sizeof(uint64_t), GET_GOID_ADDR(g_ptr));
        bpf_probe_read_user(&(e->runq_entry.pc), sizeof(uint64_t), GET_PC_ADDR(g_ptr));
        bpf_probe_read_user(&(e->runq_entry.status), sizeof(uint32_t), GET_STATUS_ADDR(g_ptr));
        bpf_probe_read_user(&g_ptr, sizeof(char *), GET_SCHEDLINK_ADDR(g_ptr));
        bpf_ringbuf_submit(e, 0);
    }

    // Report an empty entry to indicate the end of globrunq.
    e = bpf_ringbuf_reserve(&instrumentor_event, sizeof(struct globrunq_status_event), 0);
    if (!e) {
        bpf_printk("bpf_ringbuf_reserve failed in globrunq_status");
        return 1;
    }
    e->etype = EVENT_TYPE_GLOBRUNQ_STATUS;
    e->pc = pc;
    e->callerpc = callerpc;
    e->size = runq_size;
    e->runq_entry_idx = runq_size;
    e->runq_entry.pc = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

struct go_pctab {
    uint64_t size;
    uint64_t data_addr;
};

volatile const struct go_pctab pctab;

struct go_func_info {
    uint64_t entry_pc;
    uint32_t pcsp; // pcsp table (offset to pc-value table)
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __type(value, struct go_func_info);
    __uint(max_entries, 256 * 1024);
} go_functab SEC(".maps");