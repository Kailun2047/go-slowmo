//go:build ignore
#include "vmlinux.h"
#include "instrumentor.h"
#include <bpf/bpf_tracing.h>
#include <stdbool.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define GO_PARAM1(x) ((x)->ax)
#define GO_PARAM2(x) ((x)->bx)
#define GO_PARAM3(x) ((x)->cx)
#define CURR_G_ADDR(x) ((x)->r14)
#define CURR_PC(x) ((x)->ip)
#define CURR_STACK_POINTER(x) ((char *)((x)->sp))
#define CURR_FP(x) ((char *)((x)->bp))
#define MAX_LOOP_ITERS (1U << 23) // This is currently the max number of iterations permitted by eBPF loop.
#define DELAY_NS 1e9

#define P_LOCAL_RUNQ_MAX_LEN 256
#define GET_GOID_ADDR(g_addr) ((char *)(g_addr) + RUNTIME_G_GOID_OFFSET)
#define GET_M_PTR_ADDR(g_addr) ((char *)(g_addr) + RUNTIME_G_M_OFFSET)
#define GET_PC_ADDR(g_addr) ((char *)(g_addr) + RUNTIME_G_STARTPC_OFFSET)
#define GET_SCHEDLINK_ADDR(g_addr) ((char *)(g_addr) + RUNTIME_G_SCHEDLINK_OFFSET)
#define GET_P_ADDR(m_addr) ((char *)(m_addr) + RUNTIME_M_P_OFFSET)
#define GET_M_ID_ADDR(m_addr) ((char *)(m_addr) + RUNTIME_M_ID_OFFSET)
#define GET_P_ID_ADDR(p_addr) ((char *)(p_addr) + RUNTIME_P_ID_OFFSET)
#define GET_P_RUNQHEAD_ADDR(p_addr) ((char *)(p_addr) + RUNTIME_P_RUNQHEAD_OFFSET)
#define GET_P_RUNQTAIL_ADDR(p_addr) ((char *)(p_addr) + RUNTIME_P_RUNQTAIL_OFFSET)
#define GET_P_RUNQ_ADDR(p_addr) ((char *)(p_addr) + RUNTIME_P_RUNQ_OFFSET)
#define GET_P_RUNNEXT_ADDR(p_addr) ((char *)(p_addr) + RUNTIME_P_RUNNEXT_OFFSET)
#define GET_P_M_PTR_ADDR(p_addr) ((char *)(p_addr) + RUNTIME_P_M_OFFSET)

static int report_local_runq_status(uint64_t etype, uint64_t p_ptr_scalar, int64_t grouping_mid);
static int64_t unwind_stack(char *curr_stack_addr, uint64_t pc, char *curr_fp, uint64_t callstack_pc_list[]);
static long find_target_func(void *map, void *key, void *value, void *ctx);
static bool check_delay_done(uint64_t ns_start);
static void delay_helper(uint64_t delay_ns);

// C and Go could have different memory layout (e.g. aligning rule) for the
// "same" struct. uint64_t is used here to ensure consistent encoding/decoding
// of binary data even though event type can be fit into type of smaller size.
const uint64_t EVENT_TYPE_NEWPROC = 0;
const uint64_t EVENT_TYPE_DELAY = 1;
const uint64_t EVENT_TYPE_RUNQ_STATUS = 2;
// const uint64_t EVENT_TYPE_RUNQ_STEAL = 3;
// const uint64_t EVENT_TYPE_EXECUTE = 4;
const uint64_t EVENT_TYPE_GLOBRUNQ_STATUS = 5;
// const uint64_t EVENT_TYPE_SEMTABLE_STATUS = 6;
const uint64_t EVENT_TYPE_SCHEDULE = 7;
const uint64_t EVENT_TYPE_FOUND_RUNNABLE = 8;
const uint64_t EVENT_TYPE_GOPARK = 9;
const uint64_t EVENT_TYPE_GOREADY = 10;
const uint64_t EVENT_TYPE_GOREADY_RUNQ_STATUS = 11;

// C-equivalent of Go runtime.funcval struct.
struct funcval {
    uint64_t fn;
};

struct newproc_event {
    uint64_t etype;
    uint64_t newproc_pc;
    uint64_t creator_goid;
    int64_t mid;
};

struct delay_event {
    uint64_t etype;
    uint64_t pc;
    uint64_t goid;
    int64_t mid;
};

struct runq_entry {
    // A zero PC indicate an empty entry.
    uint64_t pc;
    uint64_t goid;
};

struct runq_status_event {
    uint64_t etype;
    int64_t procid;
    uint64_t runqhead;
    uint64_t runqtail;
    // The index of the reported runq entry. When runq_entry_idx = runqtail, it
    // indicates the runq_entry field holds the content of runnext, and the
    // userspace can take it as the last event of the reported runq.
    uint64_t runq_entry_idx;
    struct runq_entry runq_entry;
    int64_t mid; // -1 if runq is not yet attached to an M
    int64_t grouping_mid; // -1 if only collecting status of individual runq
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} instrumentor_event SEC(".maps");

SEC("uprobe/go_newproc")
int BPF_UPROBE(go_newproc) {
    struct newproc_event e;
    char *m_ptr;

    // Retrieve PC value of callee fn and publish to ringbuf.
    e.etype = EVENT_TYPE_NEWPROC;
    bpf_probe_read_user(&e.newproc_pc, sizeof(uint64_t), &((struct funcval *)GO_PARAM1(ctx))->fn);
    bpf_probe_read_user(&e.creator_goid, sizeof(uint64_t), GET_GOID_ADDR(CURR_G_ADDR(ctx)));
    bpf_probe_read_user(&m_ptr, sizeof(char *), GET_M_PTR_ADDR(CURR_G_ADDR(ctx)));
    bpf_probe_read_user(&e.mid, sizeof(int64_t), GET_M_ID_ADDR(m_ptr));
    bpf_ringbuf_output(&instrumentor_event, &e, sizeof(e), 0);

    delay_helper(DELAY_NS);
    
    return 0;
}

SEC("uprobe/go_runq_status")
int BPF_UPROBE(go_runq_status) {
    uint32_t runq_i, local_runq_entry_i;
    char *m_ptr, *p_ptr;

    bpf_probe_read_user(&m_ptr, sizeof(char *), GET_M_PTR_ADDR(CURR_G_ADDR(ctx)));
    bpf_probe_read_user(&p_ptr, sizeof(char *), GET_P_ADDR(m_ptr));
    // BCC treats p_ptr as non-scalar (because it is calculated by adding scalar
    // to memory reference) so we need to make report_local_runq_status accept
    // p's address as scalar value and cast p_ptr.
    return report_local_runq_status(EVENT_TYPE_RUNQ_STATUS, (uint64_t)(p_ptr), -1);
}

static int report_local_runq_status(uint64_t etype, uint64_t p_ptr_scalar, int64_t grouping_mid) {
    struct runq_status_event e;
    char *local_runq, *runnext_g_ptr, *g_ptr, *p_ptr = (char *)(p_ptr_scalar), *m_ptr;
    uint32_t runqhead, runqtail;
    uint64_t runq_i;
    int32_t procid;
    int64_t mid;

    bpf_probe_read_user(&procid, sizeof(int32_t), GET_P_ID_ADDR(p_ptr));
    bpf_probe_read_user(&runqhead, sizeof(uint32_t), GET_P_RUNQHEAD_ADDR(p_ptr));
    bpf_probe_read_user(&runqtail, sizeof(uint32_t), GET_P_RUNQTAIL_ADDR(p_ptr));
    local_runq = GET_P_RUNQ_ADDR(p_ptr);
    bpf_probe_read_user(&runnext_g_ptr, sizeof(char *), GET_P_RUNNEXT_ADDR(p_ptr));
    bpf_probe_read_user(&m_ptr, sizeof(char *), GET_P_M_PTR_ADDR(p_ptr));
    bpf_printk("RUNTIME_P_M_OFFSET: %d", RUNTIME_P_M_OFFSET);
    if (!m_ptr) {
        mid = -1;
    } else {
        bpf_probe_read_user(&mid, sizeof(int64_t), GET_M_ID_ADDR(m_ptr));
    }

    bpf_for(runq_i, runqhead, runqtail + 1) {
        e.etype = etype;
        e.runq_entry_idx = runq_i;
        e.procid = (int64_t)procid;
        e.runqhead = runqhead;
        e.runqtail = runqtail;
        e.mid = mid;
        e.grouping_mid = grouping_mid;
        if (runq_i == runqtail) {
            g_ptr = runnext_g_ptr;
        } else {
            bpf_probe_read_user(&g_ptr, sizeof(char *), (local_runq + (runq_i % P_LOCAL_RUNQ_MAX_LEN) * sizeof(char *)));
        }
        if (!g_ptr) {
            e.runq_entry.pc = 0;
        } else {
            bpf_probe_read_user(&(e.runq_entry.goid), sizeof(uint64_t), GET_GOID_ADDR(g_ptr));
            bpf_probe_read_user(&(e.runq_entry.pc), sizeof(uint64_t), GET_PC_ADDR(g_ptr));
        }
        bpf_ringbuf_output(&instrumentor_event, &e, sizeof(e), 0);
    }
    return 0;
}

SEC("uprobe/delay")
int BPF_UPROBE(delay) {
    struct delay_event e;
    char *m_ptr;
    
    e.etype = EVENT_TYPE_DELAY;
    e.pc = CURR_PC(ctx);
    bpf_probe_read_user(&e.goid, sizeof(uint64_t), GET_GOID_ADDR(CURR_G_ADDR(ctx)));
    bpf_probe_read_user(&m_ptr, sizeof(char *), GET_M_PTR_ADDR(CURR_G_ADDR(ctx)));
    bpf_probe_read_user(&e.mid, sizeof(int64_t), GET_M_ID_ADDR(m_ptr));
    bpf_ringbuf_output(&instrumentor_event, &e, sizeof(e), 0);

    delay_helper(DELAY_NS);

    return 0;
}

static void delay_helper(uint64_t delay_ns) {
    uint64_t i, ns_start;

    ns_start = bpf_ktime_get_ns();
    // Nested loops suffice for introducing a delay as long as a handful of seconds.
    bpf_for(i, 0, MAX_LOOP_ITERS) {
        if (check_delay_done(ns_start)) {
            return;
        }
    }
    bpf_printk("returning before delay duration is met");
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
#define P_SCHEDWHEN_OFFSET (RUNTIME_P_SYSMONTICK_OFFSET + RUNTIME_SYSMONTICK_SCHEDWHEN_OFFSET)

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

#define SCHED_GET_RUNQ_HEAD_ADDR(sched_addr) ((char *)(sched_addr) + RUNTIME_SCHEDT_RUNQ_OFFSET)
#define MAX_GLOBRUNQ_SIZE 16

struct globrunq_status_event {
    uint64_t etype;
    // The globrunq is a linked structure instead of a fixed-cap array (as local
    // runq is), but we have access to its size. So the userspace knows the
    // event marks the end of globrunq when runq_entry_idx = size - 1.
    int64_t size;
    uint64_t runq_entry_idx;
    struct runq_entry runq_entry;
};

SEC("uprobe/go_globrunq_status")
int BPF_UPROBE(go_globrunq_status) {
    char *g_ptr;
    int64_t runq_size;
    uint64_t runq_i;
    struct globrunq_status_event e;

    bpf_probe_read_user(&g_ptr, sizeof(char *), SCHED_GET_RUNQ_HEAD_ADDR(runtime_sched_addr));

    bpf_for(runq_i, 0, MAX_GLOBRUNQ_SIZE) {
        if (!g_ptr) {
            break;
        }
        e.etype = EVENT_TYPE_GLOBRUNQ_STATUS;
        e.size = runq_size;
        e.runq_entry_idx = runq_i;
        bpf_probe_read_user(&(e.runq_entry.goid), sizeof(uint64_t), GET_GOID_ADDR(g_ptr));
        bpf_probe_read_user(&(e.runq_entry.pc), sizeof(uint64_t), GET_PC_ADDR(g_ptr));
        bpf_probe_read_user(&g_ptr, sizeof(char *), GET_SCHEDLINK_ADDR(g_ptr));
        bpf_ringbuf_output(&instrumentor_event, &e, sizeof(e), 0);
    }

    // Report an empty entry to indicate the end of globrunq.
    e.etype = EVENT_TYPE_GLOBRUNQ_STATUS;
    e.size = runq_size;
    e.runq_entry_idx = runq_size;
    e.runq_entry.pc = 0;
    bpf_ringbuf_output(&instrumentor_event, &e, sizeof(e), 0);
    return 0;
}

#define NUM_WAITREASON 37
#define WAITREASON_STRING_MAX_LEN 40
#define GO_STRING_LEN_OFFSET 8
#define GO_STRING_SIZE 16
#define GO_STRING_LEN_ADDR(str_addr) ((char *)(str_addr) + GO_STRING_LEN_OFFSET)

volatile const uint64_t waitreason_strings_addr;

struct waitreason {
    char str[WAITREASON_STRING_MAX_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __type(value, struct waitreason);
    __uint(max_entries, NUM_WAITREASON);
} waitreason_strings SEC(".maps");

SEC("uprobe/get_waitreason_strings")
int BPF_UPROBE(get_waitreason_strings) {
    uint32_t i;
    int64_t reason_str_len;
    int ret;
    char *reason_strings_elem_ptr, *reason_str_ptr;
    struct waitreason reason;

    bpf_for(i, 0, NUM_WAITREASON) {
        reason_strings_elem_ptr = (char *)(waitreason_strings_addr + GO_STRING_SIZE * i);
        bpf_probe_read_user(&reason_str_ptr, sizeof(char *), reason_strings_elem_ptr);
        bpf_probe_read_user(&reason_str_len, sizeof(int64_t), GO_STRING_LEN_ADDR(reason_strings_elem_ptr));
        reason_str_len++; // count in the NUL byte
        if (reason_str_len > sizeof(reason.str)) {
            reason_str_len = sizeof(reason.str);
        }
        bpf_probe_read_user_str(&reason.str, reason_str_len, reason_str_ptr);
        ret = bpf_map_update_elem(&waitreason_strings, &i, &reason, BPF_EXIST);
        if (ret) {
            return ret;
        }
    }

    return 0;
}

struct gopark_event {
    uint64_t etype;
    int64_t mid;
    struct runq_entry parked;
    char waitreason[WAITREASON_STRING_MAX_LEN];
};

SEC("uprobe/go_gopark")
int BPF_UPROBE(go_gopark) {
    struct gopark_event e;
    char *m_ptr, *g_ptr;
    struct waitreason *reason_ptr;
    uint32_t waitreason_i;

    delay_helper(DELAY_NS);

    e.etype = EVENT_TYPE_GOPARK;
    waitreason_i = GO_PARAM3(ctx);
    reason_ptr = bpf_map_lookup_elem(&waitreason_strings, &waitreason_i);
    if (!reason_ptr) {
        e.waitreason[0] = 0;
    } else {
        bpf_probe_read_kernel_str(&e.waitreason, sizeof(e.waitreason), reason_ptr);
    }
    g_ptr = (char *)(CURR_G_ADDR(ctx));
    bpf_probe_read_user(&e.parked.goid, sizeof(uint64_t), GET_GOID_ADDR(g_ptr));
    bpf_probe_read_user(&e.parked.pc, sizeof(uint64_t), GET_PC_ADDR(g_ptr));
    bpf_probe_read_user(&m_ptr, sizeof(char *), GET_M_PTR_ADDR(g_ptr));
    bpf_probe_read_user(&e.mid, sizeof(int64_t), GET_M_ID_ADDR(m_ptr));
    bpf_ringbuf_output(&instrumentor_event, &e, sizeof(e), 0);

    return 0;
}

struct goready_event {
    uint64_t etype;
    int64_t mid;
    uint64_t goid;
};

SEC("uprobe/go_goready")
int BPF_UPROBE(go_goready) {
    struct goready_event e;
    char *m_ptr;

    delay_helper(DELAY_NS);

    e.etype = EVENT_TYPE_GOREADY;
    bpf_probe_read_user(&e.goid, sizeof(uint64_t), GET_GOID_ADDR(GO_PARAM1(ctx)));
    bpf_probe_read_user(&m_ptr, sizeof(char *), GET_M_PTR_ADDR(CURR_G_ADDR(ctx)));
    bpf_probe_read_user(&e.mid, sizeof(int64_t), GET_M_ID_ADDR(m_ptr));
    bpf_ringbuf_output(&instrumentor_event, &e, sizeof(e), 0);

    return 0;
}

SEC("uprobe/go_goready_runq_status")
int BPF_UPROBE(go_goready_runq_status) {
    char *m_ptr, *p_ptr;

    bpf_probe_read_user(&m_ptr, sizeof(char *), GET_M_PTR_ADDR(CURR_G_ADDR(ctx)));
    bpf_probe_read_user(&p_ptr, sizeof(char *), GET_P_ADDR(m_ptr));
    report_local_runq_status(EVENT_TYPE_GOREADY_RUNQ_STATUS, (uint64_t)p_ptr, -1);

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

#define MAX_STACK_TRACE_DEPTH 8
#define GO_FUNC_FLAG_TOP_FRAME 1

struct schedule_event {
    uint64_t etype;
    int64_t mid;
    uint64_t callstack[MAX_STACK_TRACE_DEPTH];
    int64_t callstack_depth;
    int64_t procid;
};

SEC("uprobe/go_schedule")
int BPF_UPROBE(go_schedule) {
    struct schedule_event e;
    char *m_ptr, *p_ptr;
    uint64_t pc_list[MAX_STACK_TRACE_DEPTH];
    int32_t i, procid32;

    e.etype = EVENT_TYPE_SCHEDULE;
    bpf_probe_read_user(&m_ptr, sizeof(char *), GET_M_PTR_ADDR(CURR_G_ADDR(ctx)));
    bpf_probe_read_user(&e.mid, sizeof(int64_t), GET_M_ID_ADDR(m_ptr));
    bpf_probe_read_user(&p_ptr, sizeof(char *), GET_P_ADDR(m_ptr));
    if (!p_ptr) {
        e.procid = -1;
    } else {
        bpf_probe_read_user(&procid32, sizeof(int32_t), GET_P_ID_ADDR(p_ptr));
        e.procid = (int64_t)procid32;
    }
    e.callstack_depth = unwind_stack(CURR_STACK_POINTER(ctx), CURR_PC(ctx), CURR_FP(ctx), pc_list);
    if (e.callstack_depth < 0) {
        bpf_printk("error unwinding callstack for pc %d", CURR_PC(ctx));
        return 1;
    }
    bpf_for(i, 0, MAX_STACK_TRACE_DEPTH) {
        e.callstack[i] = pc_list[i];
    }
    bpf_ringbuf_output(&instrumentor_event, &e, sizeof(e), 0);

    delay_helper(DELAY_NS);

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

struct execute_event {
    uint64_t etype;
    int64_t mid;
    struct runq_entry found; 
    uint64_t callerpc; // needed to decide if the callsite is runtime.schedule
    int64_t procid;
    uint64_t nump;
};

SEC("uprobe/go_execute")
int BPF_UPROBE(go_execute) {
    struct execute_event e;
    char *m_ptr, *p_ptr, *allp_arr_addr;
    int32_t procid32;
    int64_t allp_len;
    int i, ret;

    delay_helper(DELAY_NS);

    e.etype = EVENT_TYPE_FOUND_RUNNABLE;
    bpf_probe_read_user(&m_ptr, sizeof(char *), GET_M_PTR_ADDR(CURR_G_ADDR(ctx)));
    bpf_probe_read_user(&e.mid, sizeof(int64_t), GET_M_ID_ADDR(m_ptr));
    bpf_probe_read_user(&p_ptr, sizeof(char *), GET_P_ADDR(m_ptr));

    bpf_probe_read_user(&procid32, sizeof(int32_t), GET_P_ID_ADDR(p_ptr));
    e.procid = (int64_t)procid32;

    bpf_probe_read_user(&e.found.goid, sizeof(uint64_t), GET_GOID_ADDR(GO_PARAM1(ctx)));
    bpf_probe_read_user(&e.found.pc, sizeof(uint64_t), GET_PC_ADDR(GO_PARAM1(ctx)));
    bpf_probe_read_user(&e.callerpc, sizeof(uint64_t), CURR_STACK_POINTER(ctx));
    bpf_probe_read_user(&e.nump, sizeof(uint64_t), (char *)(allp_slice_addr + SLICE_LEN_OFFSET));
    bpf_ringbuf_output(&instrumentor_event, &e, sizeof(e), 0);

    bpf_probe_read_user(&allp_arr_addr, sizeof(char *), (char *)allp_slice_addr);
    bpf_probe_read_user(&allp_len, sizeof(int64_t), (char *)(allp_slice_addr + SLICE_LEN_OFFSET));
    bpf_probe_read_user(&m_ptr, sizeof(char *), GET_M_PTR_ADDR(CURR_G_ADDR(ctx)));
    bpf_for(i, 0, allp_len) {
        bpf_probe_read_user(&p_ptr, sizeof(char *), allp_arr_addr + sizeof(char *) * i);
        if ((ret = report_local_runq_status(EVENT_TYPE_RUNQ_STATUS, (uint64_t)p_ptr, e.mid))) {
            return ret;
        }
    }

    delay_helper(DELAY_NS);

    return 0;
}