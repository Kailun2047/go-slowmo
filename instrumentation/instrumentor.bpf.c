//go:build ignore
#include <linux/bpf.h> // TODO: replace with vmlinux.h
#include <bpf/bpf_tracing.h>
#include <stdint.h>
#include <asm/ptrace.h>
#include <stdbool.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define GO_PARAM1(x) ((x)->rax)
#define GO_PARAM2(x) ((x)->rbx)
#define GO_PARAM3(x) ((x)->rcx)
#define CURR_G_ADDR(x) ((x)->r14)
#define CURR_PC(x) ((x)->rip)
#define CURR_STACK_POINTER(x) ((char *)((x)->rsp))
#define CURR_FP(x) ((char *)((x)->rbp))
#define MAX_LOOP_ITERS (1U << 23) // This is currently the max number of iterations permitted by eBPF loop.
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
#define M_ID_OFFSET 232
#define P_LOCAL_RUNQ_MAX_LEN 256
#define P_ID_OFFSET 0
#define P_RUNQHEAD_OFFSET 400
#define P_RUNQTAIL_OFFSET 404
#define P_RUNQ_OFFSET 408
#define P_RUNNEXT_OFFSET 2456
#define GET_GOID_ADDR(g_addr) ((char *)(g_addr) + G_GOID_OFFSET)
#define GET_M_PTR_ADDR(g_addr) ((char *)(g_addr) + G_M_PTR_OFFSET)
#define GET_PC_ADDR(g_addr) ((char *)(g_addr) + G_PC_OFFSET)
#define GET_STATUS_ADDR(g_addr) ((char *)(g_addr) + G_STATUS_OFFSET)
#define GET_SCHEDLINK_ADDR(g_addr) ((char *)(g_addr) + G_SCHEDLINK_OFFSET)
#define GET_P_ADDR(m_addr) ((char *)(m_addr) + M_P_PTR_OFFSET)
#define GET_M_ID_ADDR(m_addr) ((char *)(m_addr) + M_ID_OFFSET)
#define GET_P_ID_ADDR(p_addr) ((char *)(p_addr) + P_ID_OFFSET)
#define GET_P_RUNQHEAD_ADDR(p_addr) ((char *)(p_addr) + P_RUNQHEAD_OFFSET)
#define GET_P_RUNQTAIL_ADDR(p_addr) ((char *)(p_addr) + P_RUNQTAIL_OFFSET)
#define GET_P_RUNQ_ADDR(p_addr) ((char *)(p_addr) + P_RUNQ_OFFSET)
#define GET_P_RUNNEXT_ADDR(p_addr) ((char *)(p_addr) + P_RUNNEXT_OFFSET)

static int report_local_runq_status(uint64_t p_ptr_scalar, struct pt_regs *ctx);
static int report_semtable_status(int32_t procid);
static int traverse_sudog_inorder(char *root_sudog, uint64_t semtab_version, int32_t procid);
static int traverse_sudog_waitlink(char *head_sudog, uint64_t semtab_version);
static int64_t unwind_stack(char *curr_stack_addr, uint64_t pc, char *curr_fp, uint64_t callstack_pc_list[]);
static long find_target_func(void *map, void *key, void *value, void *ctx);
static bool check_delay_done(uint64_t ns_start);

// C and Go could have different memory layout (e.g. aligning rule) for the
// "same" struct. uint64_t is used here to ensure consistent encoding/decoding
// of binary data even though event type can be fit into type of smaller size.
// const uint64_t EVENT_TYPE_NEWPROC = 0;
const uint64_t EVENT_TYPE_DELAY = 1;
const uint64_t EVENT_TYPE_RUNQ_STATUS = 2;
const uint64_t EVENT_TYPE_RUNQ_STEAL = 3;
const uint64_t EVENT_TYPE_EXECUTE = 4;
const uint64_t EVENT_TYPE_GLOBRUNQ_STATUS = 5;
const uint64_t EVENT_TYPE_SEMTABLE_STATUS = 6;
const uint64_t EVENT_TYPE_CALLSTACK = 7;

// C-equivalent of Go runtime.funcval struct.
struct funcval {
    uint64_t fn;
};

// struct newproc_event {
//     uint64_t etype;
//     uint64_t newproc_pc;
//     uint64_t creator_goid;
// };

struct delay_event {
    uint64_t etype;
    uint64_t pc;
    uint64_t goid;
    int64_t m_id;
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

// SEC("uprobe/go_newproc")
// int BPF_UPROBE(go_newproc) {
//     struct newproc_event *e;

//     // Retrieve PC value of callee fn and publish to ringbuf.
//     e = bpf_ringbuf_reserve(&instrumentor_event, sizeof(struct newproc_event), 0);
//     if (!e) {
//         bpf_printk("bpf_ringbuf_reserve failed in go_newproc");
//         return 1;
//     }
//     e->etype = EVENT_TYPE_NEWPROC;
//     bpf_probe_read_user(&e->newproc_pc, sizeof(uint64_t), &((struct funcval *)GO_PARAM1(ctx))->fn);
//     bpf_probe_read_user(&e->creator_goid, sizeof(uint64_t), GET_GOID_ADDR(CURR_G_ADDR(ctx)));
//     bpf_ringbuf_submit(e, 0);
    
//     return 0;
// }

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
    char *m_ptr, *p_ptr;

    e = bpf_ringbuf_reserve(&instrumentor_event, sizeof(struct execute_event), 0);
    if (!e) {
        bpf_printk("bpf_ringbuf_reserve failed in go_execute");
        return 1;
    }
    e->etype = EVENT_TYPE_EXECUTE;
    bpf_probe_read_user(&m_ptr, sizeof(char *), GET_M_PTR_ADDR(CURR_G_ADDR(ctx)));
    bpf_probe_read_user(&p_ptr, sizeof(char *), GET_P_ADDR(m_ptr));
    bpf_probe_read_user(&e->procid, sizeof(int32_t), GET_P_ID_ADDR(p_ptr));
    bpf_probe_read_user(&e->gopc, sizeof(char *), GET_PC_ADDR(GO_PARAM1(ctx)));
    bpf_probe_read_user(&e->goid, sizeof(char *), GET_GOID_ADDR(GO_PARAM1(ctx)));
    e->pc = CURR_PC(ctx);
    bpf_probe_read_user(&e->callerpc, sizeof(uint64_t), CURR_STACK_POINTER(ctx));
    bpf_ringbuf_submit(e, 0);

    return 0;
}

SEC("uprobe/go_runqsteal_ret_runq_status")
int BPF_UPROBE(go_runqsteal_ret_runq_status) {
    int result;
    char *m_ptr;
    uint64_t stealing_p_ptr, *stolen_p_ptr_ptr;

    bpf_probe_read_user(&m_ptr, sizeof(char *), GET_M_PTR_ADDR(CURR_G_ADDR(ctx)));
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

    bpf_probe_read_user(&m_ptr, sizeof(char *), GET_M_PTR_ADDR(CURR_G_ADDR(ctx)));
    bpf_probe_read_user(&p_ptr, sizeof(char *), GET_P_ADDR(m_ptr));
    // BCC treats p_ptr as scalar (because it is calculated by adding scalar to
    // memory reference) so we need to make report_local_runq_status accept p's
    // address as scalar value and cast p_ptr.
    return report_local_runq_status((uint64_t)(p_ptr), ctx);
}

static int report_local_runq_status(uint64_t p_ptr_scalar, struct pt_regs *ctx) {
    struct runq_status_event *e;
    char *local_runq, *runnext_g_ptr, *g_ptr, *p_ptr = (char *)(p_ptr_scalar);
    uint32_t runqhead, runqtail;
    uint64_t runq_i;
    uint64_t pc, callerpc;
    int32_t procid;

    pc = CURR_PC(ctx);
    bpf_probe_read_user(&callerpc, sizeof(uint64_t), CURR_STACK_POINTER(ctx));
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
    uint64_t i, j, ns, ns_start;
    char *m_ptr;
    
    e = bpf_ringbuf_reserve(&instrumentor_event, sizeof(struct delay_event), 0);
    if (!e) {
        bpf_printk("bpf_ringbuf_reserve failed in delay");
        return 1;
    }
    e->etype = EVENT_TYPE_DELAY;
    e->pc = CURR_PC(ctx);
    bpf_probe_read_user(&e->goid, sizeof(uint64_t), GET_GOID_ADDR(CURR_G_ADDR(ctx)));
    bpf_probe_read_user(&m_ptr, sizeof(char *), GET_M_PTR_ADDR(CURR_G_ADDR(ctx)));
    bpf_probe_read_user(&e->m_id, sizeof(int64_t), GET_M_ID_ADDR(m_ptr));
    bpf_ringbuf_submit(e, 0);

    ns_start = bpf_ktime_get_ns();
    // Nested loops suffice for introducing a delay as long as 1s.
    bpf_for(i, 0, MAX_LOOP_ITERS) {
        if (check_delay_done(ns_start)) {
            break;
        }
    }
    return 0;
}

static bool check_delay_done(uint64_t ns_start) {
    uint64_t ns, j;

    bpf_for(j, 0, MAX_LOOP_ITERS) {
        ns = bpf_ktime_get_ns();
        if (ns - ns_start >= DELAY_NS) {
            return true;
        }
    }
    return false;
}

volatile const uint64_t allp_slice_addr;

#define SLICE_LEN_OFFSET 8
#define P_SCHEDWHEN_OFFSET 32

SEC("uprobe/avoid_preempt")
int BPF_UPROBE(avoid_preempt) {
    char *allp_arr_addr, *p;
    int64_t allp_len, now = GO_PARAM1(ctx);
    int i;

    bpf_probe_read_user(&allp_arr_addr, sizeof(char *), (char *)allp_slice_addr);
    bpf_probe_read_user(&allp_len, sizeof(int64_t), (char *)(allp_slice_addr + SLICE_LEN_OFFSET));
    bpf_for(i, 0, allp_len) {
        bpf_probe_read_user(&p, sizeof(char *), allp_arr_addr + sizeof(char *) * i);
        bpf_probe_write_user(p + P_SCHEDWHEN_OFFSET, &now, sizeof(int64_t));
    }

    return 0;
}

// The compiler doesn't know runtime_sched_addr is assigned in userspace. Use
// "volatile" to avoid having runtime_sched_addr treated as an ununsed variable
// and optimized away by compiler.
volatile const uint64_t runtime_sched_addr;

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
    bpf_probe_read_user(&callerpc, sizeof(uint64_t), CURR_STACK_POINTER(ctx));
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

#define WAITREASON_SYNC_MUTEX_LOCK 21

SEC("uprobe/gopark")
int BPF_UPROBE(gopark) {
    uint8_t waitreason;
    char *m_ptr, *p_ptr;
    int32_t procid;

    waitreason = GO_PARAM3(ctx);
    if (waitreason == WAITREASON_SYNC_MUTEX_LOCK) {
        bpf_probe_read_user(&m_ptr, sizeof(char *), GET_M_PTR_ADDR(CURR_G_ADDR(ctx)));
        bpf_probe_read_user(&p_ptr, sizeof(char *), GET_P_ADDR(m_ptr));
        bpf_probe_read_user(&procid, sizeof(int32_t), GET_P_ID_ADDR(p_ptr));
        return report_semtable_status(procid);
    } else {
        bpf_printk("unprobed gopark reason %d", waitreason);
    }
    return 0;
}

volatile const uint64_t semtab_addr;
uint64_t semtab_version = 0;

#define SEMTAB_ENTRY_NUM 251
#define SEMTAB_ENTRY_SIZE 64 // size of a Go sem table entry (padding included, different under different arch)
#define SEMROOT_TREAP_OFFSET 8 // static lock rank is off by default on amd64, which means the runtime.mutex struct is 8-byte
#define SEMROOT_GET_TREAP_ADDR(semroot_addr) ((char *)(semroot_addr) + SEMROOT_TREAP_OFFSET)
#define SUDOG_NEXT_OFFSET 8
#define SUDOG_PREV_OFFSET 16
#define SUDOG_ELEM_OFFSET 24
#define SUDOG_WAITLINK_OFFSET 64 // TODO: confirm offset
#define SUDOG_GET_NEXT(sudog_addr) ((char *)(sudog_addr) + SUDOG_NEXT_OFFSET)
#define SUDOG_GET_PREV(sudog_addr) ((char *)(sudog_addr) + SUDOG_PREV_OFFSET)
#define SUDOG_GET_ELEM(sudog_addr) ((char *)(sudog_addr) + SUDOG_ELEM_OFFSET)
#define SUDOG_GET_WAITLINK(sudog_addr) ((char *)(sudog_addr) + SUDOG_WAITLINK_OFFSET)
#define MAX_TREAP_HEIGHT 10
#define MAX_WAITLIST_LEN 64

struct sudog {
    uint64_t goid;
    uint64_t elem;
};

struct semtable_status_event {
    uint64_t etype;
    // In case multiple gopark()s might get invoked concurrently on different
    // CPUs, the version field (which is atomically incremented every time
    // semtable status is reported by report_semtable_status()) is used to help
    // the user space pick the latest semtable to read among the concurrently
    // reported ones.
    uint64_t version;
    struct sudog sudog;
    // Marks the end of semtable status event stream (sudog field holds no
    // meaningful value when is_last is 1).
    uint64_t is_last;
};

static int report_semtable_status(int32_t procid) {
    struct semtable_status_event *e;
    uint8_t semroot_i;
    char *root_sudog;
    uint64_t version;
    int traverse_sudog_err;

    version = __sync_fetch_and_add(&semtab_version, 1);

    bpf_for(semroot_i, 0, SEMTAB_ENTRY_NUM) {
        bpf_probe_read_user(&root_sudog, sizeof(char *), SEMROOT_GET_TREAP_ADDR(semtab_addr + semroot_i * SEMTAB_ENTRY_SIZE));
        if (!root_sudog) {
            continue;
        }
        if ((traverse_sudog_err = traverse_sudog_inorder(root_sudog, version, procid))) {
            bpf_printk("error traversing sudog: %d", traverse_sudog_err);
            return traverse_sudog_err;
        }
    }

    e = bpf_ringbuf_reserve(&instrumentor_event, sizeof(struct semtable_status_event), 0);
    if (!e) {
        bpf_printk("bpf_ringbuf_reserve failed in report_semtable_status");
        return 1;
    }
    e->etype = EVENT_TYPE_SEMTABLE_STATUS;
    e->version = version;
    e->is_last = 1;
    bpf_ringbuf_submit(e, 0);

    return 0;
}

#define MAX_NUM_CPU 4

// The max number of logical CPUs that can be used by the tracee program needs
// to be manually restricted. It would be more flexible to have the use space
// read it via runtime.NumCPU(), but it's trickier to have the user space create
// the map first and then access the map within ebpf program.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, MAX_NUM_CPU);
    __type(key, uint32_t);
    __type(value, uint32_t);
    __array(values, struct {
        __uint(type, BPF_MAP_TYPE_STACK);
        __uint(max_entries, MAX_TREAP_HEIGHT);
        __type(value, char *);
    });
} sudog_stacks SEC(".maps");

// In-order traverse a sudog and submit the traversed sudogs as ringbuf event
// stream. Uses bpf_repeat() to approximate while() loop.
//
// TODO: an in-order traversal is not enough if we want to illustrate the tree
// structure of a treap. Maybe we need to in addition report a pre-order or
// post-order traversal.
static int traverse_sudog_inorder(char *root_sudog, uint64_t semtab_version, int32_t procid) {
    char *cur_sudog = root_sudog;
    void *sudog_stack_ptr;
    uint32_t u_procid;
    int err;

    u_procid = (uint32_t) procid;
    if (!(sudog_stack_ptr = bpf_map_lookup_elem(&sudog_stacks, &u_procid))) {
        bpf_printk("bpf_map_lookup_elem didn't find sudog_stack for semtab version %d", semtab_version);
        return 1;
    }

    bpf_repeat(MAX_TREAP_HEIGHT) {
        if (!cur_sudog) {
            break;
        }
        if ((err = bpf_map_push_elem(sudog_stack_ptr, &cur_sudog, 0))) {
            bpf_printk("bpf_map_push_elem to sudog_stack failed (might be caused by insufficient max_entries)");
            return err;
        }
        bpf_probe_read_user(&cur_sudog, sizeof(char *), SUDOG_GET_PREV(cur_sudog));
    }
    bpf_repeat(1 << MAX_TREAP_HEIGHT) {
        err = bpf_map_pop_elem(sudog_stack_ptr, &cur_sudog);
        if (err) {
            if (err == -2) { // ENOENT means the stack is empty, and we are done traversing
                break;
            } else {
                bpf_printk("bpf_map_pop_elem from sudog_stack failed: %d", err);
                return err;
            }
        }
        if ((err = traverse_sudog_waitlink(cur_sudog, semtab_version))) {
            bpf_printk("traverse_sudog_waitlink failed");
            return err;
        }
        bpf_probe_read_user(&cur_sudog, sizeof(char *), SUDOG_GET_NEXT(cur_sudog));
        bpf_repeat(MAX_TREAP_HEIGHT) {
            if (!cur_sudog) {
                break;
            }
            if ((err = bpf_map_push_elem(sudog_stack_ptr, &cur_sudog, 0))) {
                bpf_printk("bpf_map_push_elem to sudog_stack failed (might be caused by insufficient max_entries)");
                return err;
            }
            bpf_probe_read_user(&cur_sudog, sizeof(char *), SUDOG_GET_PREV(cur_sudog));
        }
    }
    return 0;
}

static int traverse_sudog_waitlink(char *head_sudog, uint64_t semtab_version) {
    struct semtable_status_event *e;
    char *sudog = head_sudog, *sudog_gp;
    uint8_t i;

    bpf_for(i, 0, MAX_WAITLIST_LEN + 1) {
        if (i == MAX_WAITLIST_LEN) {
            bpf_printk("traverse_sudog_waitlink number of linked sudogs greater than max len reserved");
            break;
        }
        if (!sudog) {
            break;
        }
        e = bpf_ringbuf_reserve(&instrumentor_event, sizeof(struct semtable_status_event), 0);
        if (!e) {
            bpf_printk("bpf_ringbuf_reserve failed in traverse_sudog_waitlink");
            return 1;
        }
        e->etype = EVENT_TYPE_SEMTABLE_STATUS;
        e->version = semtab_version;
        e->is_last = 0;
        bpf_probe_read_user(&((e->sudog).elem), sizeof(uint64_t), SUDOG_GET_ELEM(sudog));
        bpf_probe_read_user(&sudog_gp, sizeof(char *), sudog); // pointer to g is the first field of sudog struct
        bpf_probe_read_user(&((e->sudog).goid), sizeof(uint64_t), GET_GOID_ADDR(sudog_gp));
        bpf_probe_read_user(&sudog, sizeof(char *), SUDOG_GET_WAITLINK(sudog));
        bpf_ringbuf_submit(e, 0);
    }

    return 0;
}

struct go_func_info {
    uint64_t entry_pc;
    uint32_t pcsp; // pcsp table (offset to pc-value table)
    uint8_t flag; // abi.FuncFlag (can be used to determine if function is at stack root)
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __type(value, struct go_func_info);
    __uint(max_entries, 8 * 1024);
} go_functab SEC(".maps");

#define MAX_STACK_TRACE_DEPTH 32
#define MAX_PCSP_TABLE_SIZE_PER_FUNC 8 // a typical function should have 2 pcsp entries per function (before and after opening its stack frame), but assign the macro a large enough value in case of special scenarios
#define GO_FUNC_FLAG_TOP_FRAME 1
#define MAX_VARINT_SIZE_IN_BYTE 4 // the pc and value delta are variable-size encoded and decoding should iterate until 0x80 bit is 0, but hardcode a limit here since such a while loop is not viable in ebpf program

struct callstack_event {
    uint64_t etype;
    int64_t m_id;
    uint64_t callstack[MAX_STACK_TRACE_DEPTH];
    int64_t callstack_depth;
};

SEC("uprobe/get_callstack")
int BPF_UPROBE(get_callstack) {
    struct callstack_event *e;
    char *m_ptr;
    uint64_t pc_list[MAX_STACK_TRACE_DEPTH];
    int i;

    if (!(e = bpf_ringbuf_reserve(&instrumentor_event, sizeof(struct callstack_event), 0))) {
        bpf_printk("bpf_ringbuf_reserve failed in get_callstack");
        return 1;
    }
    e->etype = EVENT_TYPE_CALLSTACK;
    bpf_probe_read_user(&m_ptr, sizeof(char *), GET_M_PTR_ADDR(CURR_G_ADDR(ctx)));
    bpf_probe_read_user(&e->m_id, sizeof(int64_t), GET_M_ID_ADDR(m_ptr));
    e->callstack_depth = unwind_stack(CURR_STACK_POINTER(ctx), CURR_PC(ctx), CURR_FP(ctx), pc_list);
    if (e->callstack_depth < 0) {
        bpf_printk("error unwinding callstack for pc %d", CURR_PC(ctx));
        bpf_ringbuf_discard(e, 0);
        return 1;
    }
    bpf_for(i, 0, MAX_STACK_TRACE_DEPTH) {
        e->callstack[i] = pc_list[i];
    }
    bpf_ringbuf_submit(e, 0);
    return 0;
}

static int64_t unwind_stack(char *curr_stack_addr, uint64_t curr_pc, char *fp, uint64_t *callstack_pc_list) {
    int i;
    long go_functab_idx;
    struct go_func_info *func_info;

    bpf_for(i, 0, MAX_STACK_TRACE_DEPTH) {
        go_functab_idx = bpf_for_each_map_elem(&go_functab, &find_target_func, &curr_pc, 0) - 2;
        func_info = bpf_map_lookup_elem(&go_functab, &go_functab_idx);
        if (!func_info) {
            bpf_printk("pc %d not covered by any func in functab", curr_pc);
            return -1;
        }
        callstack_pc_list[i] = curr_pc;
        if (func_info->flag&GO_FUNC_FLAG_TOP_FRAME) {
            break;
        }

        // Frame pointer points to the stack address where the caller(if any)'s
        // RBP is pushed on. The return address is pushed before the caller's
        // RBP is pushed onto stack.
        bpf_probe_read_user(&curr_pc, sizeof(char *), fp + sizeof(char *));
        bpf_probe_read_user(&fp, sizeof(uint64_t), fp);
        if (curr_pc == 0) {
            break;
        }
    }
    return i + 1;
}

static long find_target_func(void *map, void *key, void *value, void *ctx) {
    struct go_func_info *go_func_info_value = (struct go_func_info *)value;
    uint64_t target_pc = *(uint64_t *)ctx;

    if (go_func_info_value && go_func_info_value->entry_pc > target_pc) {
        return 1;
    } else {
        return 0;
    }
}