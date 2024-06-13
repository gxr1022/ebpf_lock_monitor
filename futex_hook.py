from bcc import BPF
import errno
import datetime
import argparse

# BPF program
bpf_text = """
#include <linux/sched.h>
#include <linux/mutex.h>
#include <uapi/linux/ptrace.h>

struct key_t {
    u64 pid;
    struct mutex *lock;
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
BPF_PERF_OUTPUT(mutex);
BPF_HASH(map_mutex, struct key_t, struct data_t, 102400);

int lock_mutex(struct pt_regs *ctx, struct mutex *lock) {
    u32 current_pid = bpf_get_current_pid_tgid();
    if (current_pid == CUR_PID) {
        struct data_t data = {};
        struct key_t key = {current_pid, lock};
        struct data_t *data_ptr;
        data_ptr = map_mutex.lookup(&key);
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
            map_mutex.insert(&key, &data);
        }
    }
    return 0;
}

int release_mutex(struct pt_regs *ctx, struct mutex *lock) {
    u64 present = bpf_ktime_get_ns();
    u32 current_pid = bpf_get_current_pid_tgid();
    if (current_pid == CUR_PID) {
        struct data_t *data;
        struct key_t key = {current_pid, lock};
        data = map_mutex.lookup(&key);
        if (data) {
            data->lock_time += (present - data->ts);
            data->present_time = present;
            data->diff = present - data->ts;
            mutex.perf_submit(ctx, data, sizeof(struct data_t));
        }
    }
    return 0;
}
"""

def stack_id_err(stack_id):
    return (stack_id < 0) and (stack_id != -errno.EFAULT)

def get_stack(stack_id):
    if stack_id_err(stack_id):
        return "[Missed Stack]"
    stack = list(b.get_table("stack_traces").walk(stack_id))
    stack_str = ""
    for addr in stack:
        func_name = b.sym(addr, -1, show_module=False, show_offset=False)
        stack_str += str(func_name) + "<br>"
    return stack_str

def print_event(cpu, data, size):
    global start
    event = b["mutex"].event(data)
    if start == 0:
        start = event.ts
    time_s = (float(event.ts - start)) / 1000000000
    print("%-18.9f %-16s %-6d %-6d %-6d %-6f     %-15f %-6d" % (
        time_s, event.comm, event.pid, event.tid, event.lock,
        (float(event.present_time - start)) / 1000000000,
        event.lock_time, event.diff))
    
    trace = get_stack(event.stack_id)
    if event.lock in events:
        key = event.lock
        events[key]['ts'] = event.ts
        events[key]['lock'] = event.lock
        events[key]['present_time'] = event.present_time
        events[key]['lock_time'] += event.diff
        events[key]['tid'].add(event.tid)
        events[key]['pid'].add(event.pid)
        events[key]['comm'] = event.comm
        events[key]['lock_count'] += 1
        events[key]['type'] = event.type
        if events[key]['type'] == 2:
            events[key]['type'] = 1
        if events[key]['type'] == 4:
            events[key]['type'] = 3
        if trace in events[key]['stack_traces']:
            events[key]['stack_traces'][trace]['count'] += 1
            events[key]['stack_traces'][trace]['time'] += event.diff
        else:
            events[key]['stack_traces'][trace] = {
                'count': 1,
                'time': event.diff
            }
    else:
        event_dict = {
            'ts': event.ts,
            'lock': event.lock,
            'present_time': event.present_time,
            'lock_time': event.diff,
            'diff': event.diff,
            'tid': {event.tid},
            'pid': {event.pid},
            'comm': event.comm,
            'lock_count': 1,
            'type': event.type,
            'stack_traces': {trace: {'count': 1, 'time': event.diff}}
        }
        events[event_dict['lock']] = event_dict


parser = argparse.ArgumentParser(description='Monitor locking activities in the kernel')
parser.add_argument("--time", help="Time in seconds to monitor locks in kernel. Default value is 180 seconds",
                    type=int, default=60)
parser.add_argument("pid", help="PID of the process to trace", type=int)
args = parser.parse_args()
current_pid = args.pid

bpf_text = bpf_text.replace("CUR_PID", str(current_pid))
b = BPF(text=bpf_text)
b.attach_kprobe(event="mutex_lock", fn_name="lock_mutex")
b.attach_kprobe(event="mutex_unlock", fn_name="release_mutex")

events = {}
print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "LOCKTIME"))
print("Tracing locks for %d seconds" % args.time)

start = 0
events = {}

b["mutex"].open_perf_buffer(print_event, page_cnt=4096)
start_time = datetime.datetime.now()
try:
    while True:
        b.perf_buffer_poll()
        time_elapsed = datetime.datetime.now() - start_time
        if time_elapsed.seconds > args.time:
            break
except KeyboardInterrupt:
    pass
finally:
    # min_lock_time = min(event['diff'] for event in events.values())
    # print("\nMinimum lock time is : %d\n" % min_lock_time)

    print("Events collected during tracing:")
    for lock, event_data in events.items():
        print(f"Lock Address: {lock}")
        print(f"  Total Lock Time: {event_data['lock_time']} ns")
        print(f"  Lock Count: {event_data['lock_count']}")
        print(f"  PIDs: {event_data['pid']}")
        print(f"  TIDs: {event_data['tid']}")
        print("  Stack Traces:")
        for trace, trace_info in event_data['stack_traces'].items():
            print(f"    Trace: {trace}")
            print(f"      Count: {trace_info['count']}")
            print(f"      Time: {trace_info['time']} ns")
        print()