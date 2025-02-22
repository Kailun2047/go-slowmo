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
    uint32_t runqhead;
    uint32_t runqtail;
    struct runq_entry local_runq[P_LOCAL_RUNQ_MAX_LEN];
    struct runq_entry runnext;
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
    __uint(max_entries, 8);
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
    uint32_t runq_i, local_runq_entry_i, local_runq_entry_num;
    char *m_ptr, *p_ptr;

    bpf_probe_read_user(&m_ptr, sizeof(char *), GET_M_ADDR(CURR_G_ADDR(ctx)));
    bpf_probe_read_user(&p_ptr, sizeof(char *), GET_P_ADDR(m_ptr));
    if (!p_ptr) {
        return 1;
    }
    // BCC treats p_ptr as scalar (because it is calculated by adding scalar to
    // memory reference) so we need to make report_local_runq_status accept p's
    // address as scalar value and cast p_ptr.
    return report_local_runq_status((uint64_t)(p_ptr), ctx);
}

int report_local_runq_status(uint64_t p_ptr_scalar, struct pt_regs *ctx) {
    struct runq_status_event *e;
    char *local_runq, *runnext_g_ptr, *g_ptr, *p_ptr = (char *)(p_ptr_scalar);
    uint32_t runq_i, local_runq_entry_i, local_runq_entry_num;

    e = bpf_ringbuf_reserve(&instrumentor_event, sizeof(struct runq_status_event), 0);
    if (!e) {
        bpf_printk("bpf_ringbuf_reserve failed in go_runtime_func_ret_runq_status");
        return 1;
    }
    e->etype = EVENT_TYPE_RUNQ_STATUS;
    e->pc = CURR_PC(ctx);
    bpf_probe_read_user(&e->callerpc, sizeof(uint64_t), CURR_STACK_TOP(ctx));
    bpf_probe_read_user(&e->procid, sizeof(int32_t), GET_P_ID_ADDR(p_ptr));
    bpf_probe_read_user(&e->runqhead, sizeof(uint32_t), GET_P_RUNQHEAD_ADDR(p_ptr));
    bpf_probe_read_user(&e->runqtail, sizeof(uint32_t), GET_P_RUNQTAIL_ADDR(p_ptr));
    local_runq = GET_P_RUNQ_ADDR(p_ptr);
    bpf_probe_read_user(&runnext_g_ptr, sizeof(char *), GET_P_RUNNEXT_ADDR(p_ptr));
    bpf_probe_read_user(&e->runnext.goid, sizeof(uint64_t), GET_GOID_ADDR(runnext_g_ptr));
    bpf_probe_read_user(&e->runnext.pc, sizeof(uint64_t), GET_PC_ADDR(runnext_g_ptr));
    bpf_probe_read_user(&e->runnext.status, sizeof(uint32_t), GET_STATUS_ADDR(runnext_g_ptr));

    // Store (e->runqhead - e->runqtail) into local variable and check it in
    // every iteration to prevent the verifier from complaining about potential
    // unbounded memory access.
    local_runq_entry_num = e->runqtail - e->runqhead;
    local_runq_entry_i = e->runqhead % P_LOCAL_RUNQ_MAX_LEN;
    for (runq_i = 0; runq_i < local_runq_entry_num; runq_i++) {
        local_runq_entry_i = (local_runq_entry_i + runq_i) % P_LOCAL_RUNQ_MAX_LEN;
        bpf_probe_read_user(&g_ptr, sizeof(char *), (local_runq + local_runq_entry_i * sizeof(char *)));
        bpf_probe_read_user(&(e->local_runq[local_runq_entry_i].goid), sizeof(uint64_t), GET_GOID_ADDR(g_ptr));
        bpf_probe_read_user(&(e->local_runq[local_runq_entry_i].pc), sizeof(uint64_t), GET_PC_ADDR(g_ptr));
        bpf_probe_read_user(&(e->local_runq[local_runq_entry_i].status), sizeof(uint32_t), GET_STATUS_ADDR(g_ptr));
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
    // runq is). We chunk it into fixed-cap arrays if needed and put each array
    // ("runq") into a ringbuf entry. In addition an extra field ("size") is
    // used to indicate the length of each array, so when a ringbuf entry has
    // size less then P_LOCAL_RUNQ_MAX_LEN we know it's the last chunk.
    uint64_t size;
    struct runq_entry runq[P_LOCAL_RUNQ_MAX_LEN];
};

// Make sure the target attachmend point of this probe has exclusive access to
// the lock of globrunq (this should hold true for most, if not all, functions
// that read/write the runtime.sched global variable), so that the submitted
// ringbuf entries are not interleaved.
SEC("uprobe/globrunq_status")
int BPF_UPROBE(globrunq_status) {
    char *g_ptr;
    uint64_t pc, callerpc;
    int32_t runq_i, runq_size, curr_runq_i;
    struct globrunq_status_event *e;

    pc = CURR_PC(ctx);
    bpf_probe_read_user(&callerpc, sizeof(uint64_t), CURR_STACK_TOP(ctx));
    bpf_probe_read_user(&g_ptr, sizeof(char *), SCHED_GET_RUNQ_HEAD_ADDR(runtime_sched_addr));
    bpf_probe_read_user(&runq_size, sizeof(int32_t), SCHED_GET_RUNQ_SIZE_ADDR(runtime_sched_addr));
    e = bpf_ringbuf_reserve(&instrumentor_event, sizeof(struct globrunq_status_event), 0);
    if (!e) {
        bpf_printk("bpf_ringbuf_reserve failed in globrunq_status");
        return 1;
    }
    e->etype = EVENT_TYPE_GLOBRUNQ_STATUS;
    e->pc = pc;
    e->callerpc = callerpc;
    for (runq_i = 0; runq_i < runq_size; runq_i++) {
        curr_runq_i = runq_i % P_LOCAL_RUNQ_MAX_LEN;
        if (runq_i > 0 && curr_runq_i == 0) {
            e->size = P_LOCAL_RUNQ_MAX_LEN;
            bpf_ringbuf_submit(e, 0);
            e = bpf_ringbuf_reserve(&instrumentor_event, sizeof(struct globrunq_status_event), 0);
            if (!e) {
                bpf_printk("bpf_ringbuf_reserve failed in globrunq_status");
                return 1;
            }
            e->etype = EVENT_TYPE_GLOBRUNQ_STATUS;
            e->pc = pc;
            e->callerpc = callerpc;
        }
        bpf_probe_read_user(&(e->runq[curr_runq_i].goid), sizeof(uint64_t), GET_GOID_ADDR(g_ptr));
        bpf_probe_read_user(&(e->runq[curr_runq_i].pc), sizeof(uint64_t), GET_PC_ADDR(g_ptr));
        bpf_probe_read_user(&(e->runq[curr_runq_i].status), sizeof(uint32_t), GET_STATUS_ADDR(g_ptr));
        bpf_probe_read_user(&g_ptr, sizeof(char *), GET_SCHEDLINK_ADDR(g_ptr));
        // The verifier will report an error if the total number of iterations
        // is unbounded (which is the case for "runq_size" since its value is
        // read dynamically at runtime). Set a max allowable iteration count as
        // a workaround here.
        if (runq_size > P_LOCAL_RUNQ_MAX_LEN * 4) {
            bpf_printk("globrunq size %d is greater than the max length that can be handled");
            bpf_ringbuf_discard(e, 0);
            return 1;
        }
    }
    e->size = runq_i % P_LOCAL_RUNQ_MAX_LEN;
    bpf_ringbuf_submit(e, 0);   
    return 0;
}