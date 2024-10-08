#!/usr/bin/env python
from bcc import BPF
import errno
import datetime
import argparse
import numpy as np


bpf_prog = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
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
    u64 func_addr = PT_REGS_PARM1(ctx);; 
    struct data_t data = {};
    struct data_t *data_ptr;
    data_ptr=lock_hash_table.lookup(&func_addr);
    u32 current_pid = bpf_get_current_pid_tgid() >> 32;
    u32 current_tid = bpf_get_current_pid_tgid();
    if (current_tid == target_TID) {
        bpf_trace_printk("Trace function: TID=%u, func_addr=0x%llx\\n", current_tid, (u64)func_addr); // Debugging
        if(data_ptr)
        {
            data_ptr->time_s=bpf_ktime_get_ns();
            data_ptr->lock_count += 1;
            data_ptr->stack_id = stack_traces.get_stackid(ctx, BPF_F_REUSE_STACKID|BPF_F_USER_STACK);
            bpf_trace_printk("Lock count: %d \\n", data_ptr->lock_count); // Debugging
        }
        else{
            data.tid=bpf_get_current_pid_tgid();
            data.time_s=bpf_ktime_get_ns();
            bpf_get_current_comm(&data.comm, sizeof(data.comm));   
            data.func_addr=func_addr;
            data.stack_id = stack_traces.get_stackid(ctx, BPF_F_REUSE_STACKID|BPF_F_USER_STACK);
            data.lock_count = 1;
            lock_hash_table.insert(&func_addr,&data);
        }
    }
    
    
}

void trace_end(struct pt_regs* ctx) {
    u64 func_addr = PT_REGS_PARM1(ctx);  // get the first parameter of pthread function.
    u32 current_pid = bpf_get_current_pid_tgid() >> 32;
    u32 current_tid = bpf_get_current_pid_tgid();
    if (current_tid == target_TID) {
        struct data_t *data;
        data = lock_hash_table.lookup(&func_addr);
        if (data) {
            bpf_trace_printk("Return function: TID=%u, func_addr=0x%llx\\n", current_tid, (u64)func_addr); // Debugging
            data->time_e = bpf_ktime_get_ns();
            if(data->time_e <= data->time_s)
                return;
            data->time_delta = data->time_e - data->time_s;
            data->lock_accum_time += data->time_delta;
            perf_output.perf_submit(ctx, data, sizeof(struct data_t));
        }
    }
    
}

"""


def get_stack(stack_id):
    if stack_id_err(stack_id):
        return "[Missed Stack]"
    stack = list(b.get_table("stack_traces").walk(stack_id))
    # print("Stack addresses:", [hex(addr) for addr in stack])  
    stack_str = ""
    for addr in stack:
        func_name = b.sym(addr, args.pid, True) #Translate a memory address into a kernel function name
        stack_str += "\n"+"    "+str(func_name)
    return stack_str

def stack_id_err(stack_id):
    # -EFAULT in get_stackid normally means the stack-trace is not available,
    # Such as getting kernel stack trace in userspace code
    return (stack_id < 0) and (stack_id != -errno.EFAULT)

def print_event(cpu, data, size):
        event = b["perf_output"].event(data)
        # print("%-18.9d %-16s %-6d %-15d %-6d" % (event.func_addr, event.comm, event.tid,event.lock_accum_time, event.time_delta))
        stack = b["stack_traces"].walk(event.stack_id)
        trace = get_stack(event.stack_id)
        key = event.func_addr
        if key in events:
            events[key]['time_s'] = event.time_s
            events[key]['func_addr'] = event.func_addr
            events[key]['time_e'] += event.time_e
            events[key]['tid'].add(event.tid)
            events[key]['time_delta']=event.time_delta
            events[key]['lock_accum_time']+=event.time_delta
            events[key]['comm'] = event.comm
            events[key]['lock_count'] += 1
            if trace in events[key]['stack_traces']:
                events[key]['stack_traces'][trace]['count'] += 1
                events[key]['stack_traces'][trace]['time'] += event.time_delta
            else:
                events[key]['stack_traces'][trace] = {
                    'count': 1,
                    'time': event.time_delta
            }
        else:
            event_dict = {
                'time_s': event.time_s,
                'func_addr': event.func_addr,
                'time_e': event.time_e,
                'lock_accum_time': event.lock_accum_time,
                'time_delta': event.time_delta,
                'tid': {event.tid},
                'comm': event.comm,
                'lock_count': 1,
                'func_name': "pthread_mutex_lock/unlock",
                'stack_traces': {trace: {'count': 1, 'time': event.time_delta}}
            }
            events[event_dict['func_addr']] = event_dict

def print_func_info(events):
    print("Events collected during tracing:")
    for func, event_data in events:
        print(f"Func Address: {func:#014x}")
        print(f"  Func Name: {event_data['func_name']}")
        print(f"  Total Lock Time: {event_data['lock_accum_time']} ns")
        print(f"  Lock Count: {event_data['lock_count']}")
        print(f"  TIDs: {event_data['tid']}")        
        print("  Stack Traces:")
        for trace, trace_info in event_data['stack_traces'].items():
            print(f"      Count: {trace_info['count']}")
            print(f"      Time: {trace_info['time']} ns")
            print(f"    Trace: {trace}")
            

parser = argparse.ArgumentParser(description="Trace functions in MongoDB")
parser.add_argument("-t","--time", help="Time in seconds to monitor locks in kernel. Default value is 180 seconds",
                    type=int, default=30)
parser.add_argument("-p", "--pid", type=int, help="PID of the target process",default=-1)
parser.add_argument("-s", "--tid", type=int, help="TID of the target process",default=-1)
parser.add_argument("-l", "--lib",  help="Library name containing symbol to trace, e.g. /usr/bin/mongod", type=str, default="/lib/x86_64-linux-gnu/libc.so.6")
parser.add_argument("-e", "--sym_e", help="Symbol to trace, e.g. pthread_mutex_init", type=str, default="pthread_mutex_lock")
parser.add_argument("-r", "--sym_r",  help="Symbol to trace, e.g. pthread_mutex_init", type=str, default="pthread_mutex_lock")

args = parser.parse_args()

bpf_prog = bpf_prog.replace("target_TID", str(args.tid))

try:
    b = BPF(text=bpf_prog)
except Exception as e:
    print(f"Failed to compile BPF program: {e}")
    exit(1)



events={}

b.attach_uprobe(name=args.lib, sym=args.sym_e, fn_name="trace_start", pid=args.pid)
b.attach_uretprobe(name=args.lib, sym=args.sym_r, fn_name="trace_end", pid=args.pid)


b["perf_output"].open_perf_buffer(print_event)

start_time = datetime.datetime.now()
try:
    while True:
        # b.trace_print()
        b.perf_buffer_poll()
        time_elapsed = datetime.datetime.now() - start_time
        if time_elapsed.seconds > args.time:
            break
except KeyboardInterrupt:
    pass
finally:
    event_list = sorted(events.items(), key=lambda kv: kv[1]['lock_accum_time'], reverse=False) 
    print_func_info(event_list)
