
#include <linux/sched.h>
#include <linux/mutex.h>
#include <uapi/linux/ptrace.h>
struct key_mutex_t {
    u64 pid;
    struct mutex *lock;
};

struct key_spin_t {
    u64 pid;
    raw_spinlock_t *lock;
};

struct data_t {
    u32 pid;
    u32 tid;
    u64 ts;
    char comm[TASK_COMM_LEN];
    u64 lock;
    u64 lock_time;
    u64 present_time;
    u64 diff;
    u64 stack_id;
    u32 lock_count;
};

BPF_STACK_TRACE(stack_traces, 102400);


BPF_PERF_OUTPUT(spin);
BPF_HASH(map_spin, struct key_spin_t, struct data_t, 102400);

int lock_spin(struct pt_regs *ctx, raw_spinlock_t *lock) {
    u32 current_pid = bpf_get_current_pid_tgid()>> 32;
    if (current_pid == 275381) {
        bpf_trace_printk("Locking mutex: PID=%u, lock=0x%llx\n", current_pid, (u64)lock); // Debugging
        struct data_t data = {};
        struct key_spin_t key = {current_pid, lock};
        struct data_t *data_ptr;
        data_ptr = map_spin.lookup(&key);
        if (data_ptr) {
            data_ptr->ts = bpf_ktime_get_ns();
            data_ptr->lock_count += 1;
            data_ptr->stack_id = stack_traces.get_stackid(ctx, BPF_F_REUSE_STACKID);
        } else {
            data.pid = bpf_get_current_pid_tgid();
            data.tid = bpf_get_current_pid_tgid() >> 32;
            bpf_get_current_comm(&data.comm, sizeof(data.comm));        
            data.lock = (u64)lock;
            data.ts = bpf_ktime_get_ns();
            data.lock_count = 1;
            data.stack_id = stack_traces.get_stackid(ctx, BPF_F_REUSE_STACKID);
            map_spin.insert(&key, &data);
        }
    }
    return 0;
}

int release_spin(struct pt_regs *ctx, raw_spinlock_t *lock) {
    u64 present = bpf_ktime_get_ns();
    u32 current_pid = bpf_get_current_pid_tgid()>> 32;
    if (current_pid == 275381) {
        bpf_trace_printk("Releasing mutex: PID=%u, lock=0x%llx\n", current_pid, (u64)lock); // Debugging
        struct data_t *data;
        struct key_spin_t key = {current_pid, lock};
        data = map_spin.lookup(&key);
        if (data) {
            data->lock_time += (present - data->ts);
            data->present_time = present;
            data->diff = present - data->ts;
            spin.perf_submit(ctx, data, sizeof(struct data_t));
        }
    }
    return 0;
}

TIME(s)            COMM             PID    LOCKTIME
Tracing locks for 60 seconds
Events collected during tracing:
The total count of acquiring spin lock is:  0
The total time of acquiring spin lock is:  0.0 s
