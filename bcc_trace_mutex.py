from bcc import BPF
import errno
import datetime
import argparse

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

def print_event(cpu, data, size):
    global start
    event = b["spin"].event(data)
    # event = b["mutex"].event(data)
    if start == 0:
        start = event.ts
    time_s = (float(event.ts - start)) / 1000000000
    # print("%-18.9f %-16s %-6d %-6d %-6d %-6f     %-15f %-6d" % (
    #     time_s, event.comm, event.pid, event.tid, event.lock,
    #     (float(event.present_time - start)) / 1000000000,
    #     event.lock_time, event.diff))
    
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
        # events[key]['type'] = event.type
        # if events[key]['type'] == 2:
        #     events[key]['type'] = 1
        # if events[key]['type'] == 4:
        #     events[key]['type'] = 3
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
            # 'type': event.type,
            'stack_traces': {trace: {'count': 1, 'time': event.diff}}
        }
        events[event_dict['lock']] = event_dict


parser = argparse.ArgumentParser(description='Monitor locking activities in the kernel')
parser.add_argument("--time", help="Time in seconds to monitor locks in kernel. Default value is 180 seconds",
                    type=int, default=60)
parser.add_argument("--pid", help="PID of the process to trace", type=int)
args = parser.parse_args()
current_pid = args.pid

with open('trace_mutexlock.c', 'r') as f:
    bpf_text = f.read()

bpf_text = bpf_text.replace("target_PID", str(current_pid))

print(current_pid)

try:
    b = BPF(text=bpf_text)
except Exception as e:
    print(f"Failed to compile BPF program: {e}")
    exit(1)

# b.attach_kprobe(event="mutex_lock", fn_name="lock_mutex")
# b.attach_kprobe(event="mutex_unlock", fn_name="release_mutex")

b.attach_kprobe(event="_raw_spin_lock", fn_name="lock_raw_spin")
b.attach_kprobe(event="_raw_spin_unlock", fn_name="release_raw_spin")

# b.attach_kprobe(event="_raw_read_lock", fn_name="lock_raw_read")
# b.attach_kprobe(event="_raw_read_unlock", fn_name="release_raw_read")

# b.attach_kprobe(event="_raw_write_lock", fn_name="lock_raw_write")
# b.attach_kprobe(event="_raw_write_unlock", fn_name="release_raw_write")

events = {}
print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "LOCKTIME"))
print("Tracing locks for %d seconds" % args.time)

start = 0
events = {}

# b["mutex"].open_perf_buffer(print_event, page_cnt=4096)
b["spin"].open_perf_buffer(print_event, page_cnt=65536)
start_time = datetime.datetime.now()
try:
    while True:
        
        # b.trace_print()
        time_elapsed = datetime.datetime.now() - start_time
        if time_elapsed.seconds > args.time:
            break
        b.perf_buffer_poll()
except KeyboardInterrupt:
    pass
finally:
    # min_lock_time = min(event['diff'] for event in events.values())
    # print("\nMinimum lock time is : %d\n" % min_lock_time)
    total_lock_time = 0.0
    total_lock_count = 0
    print("Events collected during tracing:")
    for lock, event_data in events.items():
        print(f"Lock Address: {lock}")
        print(f"  Total Lock Time: {event_data['lock_time']} ns")
        print(f"  Lock Count: {event_data['lock_count']}")
        print(f"  PIDs: {event_data['pid']}")
        print(f"  TIDs: {event_data['tid']}")
        print("  Stack Traces:")
        total_lock_time+=event_data['lock_time']
        total_lock_count+=event_data['lock_count']
        for trace, trace_info in event_data['stack_traces'].items():
            print(f"    Trace: {trace}")
            print(f"      Count: {trace_info['count']}")
            print(f"      Time: {trace_info['time']} ns")
        print()
    total_lock_time_seconds = total_lock_time / 1000000000
    print("The total count of acquiring spin lock is: ",total_lock_count)
    print("The total time of acquiring spin lock is: ",total_lock_time_seconds, "s")