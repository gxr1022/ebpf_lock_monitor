#include <uapi/linux/ptrace.h>

struct data_t {
    u32 tid;
    u64 time_s;
    char comm[TASK_COMM_LEN];
    u64 func_addr;
    u64 lock_accum_time;
    u64 time_e;
    u64 time_delta;
    u64 stack_id;
    u32 lock_count;
};

BPF_STACK_TRACE(stack_traces, 102400);
BPF_PERF_OUTPUT(perf_output);
BPF_HASH(lock_hash_table, u64, struct data_t, 102400);

void trace_start(struct pt_regs *ctx)
{
    u64 func_addr = PT_REGS_IP(ctx); 
    struct data_t data = {};
    struct data_t *data_ptr;
    data_ptr=lock_hash_table.lookup(func_addr);
    if(data_ptr)
    {
        data_ptr->time_s=bpf_ktime_get_ns();
        data_ptr->lock_count += 1;
        data_ptr->stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);
    }
    else{
        data.tid=bpf_get_current_pid_tgid();
        data.time_s=bpf_ktime_get_ns();
        bpf_get_current_comm(&data.comm, sizeof(data.comm));   
        data.func_addr=func_addr;
        data.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);
        data.lock_count = 1;
        lock_hash_table.insert(data.func_addr,&data);
    }
}

void trace_end(struct pt_regs* ctx) {
    u64 func_addr = PT_REGS_IP(ctx); 
    u32 current_tid = bpf_get_current_pid_tgid();

    bpf_trace_printk("Return function: TID=%u, func_addr=0x%llx\\n", current_tid, (u64)func_addr); // Debugging
    struct data_t *data;
    data = map_LOCK_NAME.lookup(func_addr);
    if (data) {
        data->time_e = bpf_ktime_get_ns();
        if(data->time_e <= data->time_s)
            return;
        data->time_delta = data->time_e - data->time_s;
        data->lock_time += data->time_delta;
        perf_output.perf_submit(ctx, data, sizeof(struct data_t));
    }
}
