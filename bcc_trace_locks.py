from bcc import BPF
import errno
import datetime
import argparse
import numpy as np
# import matplotlib.pyplot as plt

locks = [
    {
         'lock_name': 'mutex',
         'title': 'Mutex',
         'lock_type': 'struct mutex',
         'key_type': 'key_mutex_t',
         'lock_func': 'mutex'
     },
    #  {
    #      'lock_name': 'spin',
    #      'title': 'Spin Lock',
    #      'lock_type': 'raw_spinlock_t',
    #      'key_type': 'key_spin_t',
    #      'lock_func': '_raw_spin'
    #  },
     {
         'lock_name': 'write_lock',
         'title': 'Write Lock',
         'lock_type': 'rwlock_t',
         'key_type': 'key_rw_t',
         'lock_func': '_raw_write'
     },
     {
         'lock_name': 'read_lock',
         'title': 'Read Lock',
         'lock_type': 'rwlock_t',
         'key_type': 'key_rw_t',
         'lock_func': '_raw_read'
     }
]

prog_header = """
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

struct key_rw_t {
    u64 pid;
    rwlock_t *lock;
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

"""

lock_func = """
BPF_PERF_OUTPUT(LOCK_NAME);
BPF_HASH(map_LOCK_NAME, struct KEY_TYPE, struct data_t, 102400);

int lock_LOCK_NAME(struct pt_regs *ctx, LOCK_TYPE *lock) {
    u32 current_pid = bpf_get_current_pid_tgid()>> 32;
    if (current_pid == target_PID) {
        bpf_trace_printk("Locking mutex: PID=%u, lock=0x%llx\\n", current_pid, (u64)lock); // Debugging
        struct data_t data = {};
        struct KEY_TYPE key = {current_pid, lock};
        struct data_t *data_ptr;
        data_ptr = map_LOCK_NAME.lookup(&key);
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
            map_LOCK_NAME.insert(&key, &data);
        }
    }
    return 0;
}

int release_LOCK_NAME(struct pt_regs *ctx, LOCK_TYPE *lock) {
    u64 present = bpf_ktime_get_ns();
    u32 current_pid = bpf_get_current_pid_tgid()>> 32;
    if (current_pid == target_PID) {
        bpf_trace_printk("Releasing mutex: PID=%u, lock=0x%llx\\n", current_pid, (u64)lock); // Debugging
        struct data_t *data;
        struct KEY_TYPE key = {current_pid, lock};
        data = map_LOCK_NAME.lookup(&key);
        if (data) {
            data->lock_time += (u64)(present - data->ts);
            data->present_time = present;
            data->diff = present - data->ts;
            LOCK_NAME.perf_submit(ctx, data, sizeof(struct data_t));
        }
    }
    return 0;
}
"""

def generate_report(event_list):
    # Generating box plot
    box_data = {}
    lock_times = {}
    for lock in locks:
        lock_times[lock['lock_name']] = []
    for event in event_list:
        lock_times[event[1]['lock_name']].append(event[1]['lock_time'])
    for lock in locks:
        lock_times_list = np.array(lock_times[lock['lock_name']])
        box_data[lock['lock_name']] = [np.min(lock_times_list),
                                  np.percentile(lock_times_list, 25),
                                  np.percentile(lock_times_list, 50),
                                  np.percentile(lock_times_list, 75),
                                  np.percentile(lock_times_list, 90),
                                  ]
    print(box_data)
    # plot_boxgra(box_data)

# def plot_boxgra(lock_data):
#     plt.figure(figsize=(8, 6))
#     plt.boxplot(lock_data.values(), labels=lock_data.keys())
#     plt.title('Boxplot of Lock Types')
#     plt.xlabel('Lock Types')
#     plt.ylabel('Lock Time')
#     plt.grid(True)
#     plt.show()

def stack_id_err(stack_id):
    return (stack_id < 0) and (stack_id != -errno.EFAULT)

def get_stack(stack_id):
    if stack_id_err(stack_id):
        return "[Missed Stack]"
    stack = list(b.get_table("stack_traces").walk(stack_id))
    stack_str = ""
    for addr in stack:
        func_name = b.sym(addr, -1, show_module=False, show_offset=False) #Translate a kernel memory address into a kernel function name
        stack_str += str(func_name) + "<br>"
    return stack_str

def print_lock_info(events):
    print("Events collected during tracing:")
    for lock, event_data in events:
        print(f"Lock Address: {lock}")
        print(f"  Lock Name: {event_data['lock_name']}")
        print(f"  Total Lock Time: {event_data['lock_time']} ns")
        print(f"  Lock Count: {event_data['lock_count']}")
        print(f"  PIDs: {event_data['pid']}")
        print(f"  TIDs: {event_data['tid']}")        
        print("  Stack Traces:")
        for trace, trace_info in event_data['stack_traces'].items():
            print(f"    Trace: {trace}")
            print(f"      Count: {trace_info['count']}")
            print(f"      Time: {trace_info['time']} ns")

def create_print_event(lock_name):
    def print_event(cpu, data, size):
        global start
        event = b[lock_name].event(data)
        if start == 0:
            start = event.ts
        time_s = (float(event.ts - start)) / 1000000000
        print("%-18.9f %-16s %-6d %-6d %-6d %-6f     %-15f %-6d" % (
            time_s, event.comm, event.pid, event.tid, event.lock,
            (float(event.present_time - start)) / 1000000000,
            event.lock_time, event.diff))
        print(lock_name,"\n")
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
                'lock_name': lock_name,
                'stack_traces': {trace: {'count': 1, 'time': event.diff}}
            }
            events[event_dict['lock']] = event_dict
    return print_event

parser = argparse.ArgumentParser(description='Monitor locking activities in the kernel')
parser.add_argument("--time", help="Time in seconds to monitor locks in kernel. Default value is 180 seconds",
                    type=int, default=120)
parser.add_argument("--pid", help="PID of the process to trace", type=int)
args = parser.parse_args()
current_pid = args.pid


prog = prog_header
for lock in locks:
    prog += lock_func.replace("LOCK_NAME", str(lock['lock_name'])).replace("KEY_TYPE", lock['key_type']).replace("LOCK_TYPE", lock['lock_type'])
prog = prog.replace("target_PID", str(current_pid))



try:
    b = BPF(text=prog)
except Exception as e:
    print(f"Failed to compile BPF program: {e}")
    exit(1)

for lock in locks:
    b.attach_kprobe(event="%s_lock" % lock['lock_func'], fn_name="lock_%s" % lock['lock_name'])
    b.attach_kprobe(event="%s_unlock" % lock['lock_func'], fn_name="release_%s" % lock['lock_name']) # unlock is better
    print(f"Attached kprobe to %s_lock and kretprobe to %s_unlock" % (lock['lock_func'], lock['lock_func']))



events = {}
lock_statistics={}
print("Tracing  locks for %d seconds" % args.time)
print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "LOCKTIME"))


start = 0
events = {}
lock_statistics={}

for lock in locks:
    lock_statistics[lock['lock_name']] = {
        'total_lock_count': 0,
        'total_lock_time': 0.0
    }
    b[lock['lock_name']].open_perf_buffer(create_print_event(lock['lock_name']), page_cnt=8192)

start_time = datetime.datetime.now()
try:
    while True:
        time_elapsed = datetime.datetime.now() - start_time
        if time_elapsed.seconds > args.time:
            break
        # b.trace_print()
        b.perf_buffer_poll()
except KeyboardInterrupt:
    pass
finally:
    total_lock_time = 0.0
    total_lock_count = 0
    for lock, event_data in events.items():
        key=event_data['lock_name']
        lock_statistics[key]['total_lock_count'] +=event_data['lock_count']
        lock_statistics[key]['total_lock_time'] +=event_data['lock_time']
        total_lock_time+=event_data['lock_time']
    
    print("\n Print the lock statistics: ")
    print("%-18s %-16s %s" % ("LOCK_NAME", "TOTAL_LOCKTIME(s)", "TOTAL_LOCKCOUNT"))
    for lock_name, lock_stat in lock_statistics.items():
        print("%-18s %-16f %s" % (lock_name, lock_stat['total_lock_time'] / 1000000000, lock_stat['total_lock_count']))
    print("The total time of acquiring locks is:",total_lock_time / 1000000000.0,"s")  
    
    event_list = sorted(events.items(), key=lambda kv: kv[1]['lock_time'], reverse=False)
    
    print_lock_info(event_list)
    # print(event_list)
    generate_report(event_list)



    
