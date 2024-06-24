import sys
import itertools
from time import sleep
from bcc import BPF
import signal
import ctypes

# define BPF program
prog = """
#include <linux/ptrace.h>
#include <linux/ktime.h>

struct mutex_use_t {
	u32 pid;
	int stack_id;
	u64 mtx;
};

BPF_HASH(lock_stacks, u64, struct mutex_use_t);
BPF_STACK_TRACE(stacks, 4096);

int probe_mutex_lock(struct pt_regs *ctx)
{
    u64 now = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid();
    int stack_id = stacks.get_stackid(ctx, BPF_F_REUSE_STACKID|BPF_F_USER_STACK);
    u64 mutex_addr = PT_REGS_PARM1(ctx);

    struct mutex_use_t val = {};
    val.pid = pid;
    val.stack_id = stack_id;
    val.mtx = mutex_addr;
    lock_stacks.update(&now, &val);
    bpf_trace_printk("Pthread mutex lock\\n");
    return 0;
}

int probe_mutex_unlock(struct pt_regs *ctx)
{
    u64 now = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid();
    int stack_id = stacks.get_stackid(ctx, BPF_F_REUSE_STACKID|BPF_F_USER_STACK);
    u64 mutex_addr = PT_REGS_PARM1(ctx);

    struct mutex_use_t val = {};
    val.pid = pid;
    val.stack_id = stack_id;
    val.mtx = mutex_addr;
    lock_stacks.update(&now, &val);
    bpf_trace_printk("Pthread mutex lock\\n");
    return 0;
}
"""

def attach(bpf):
    bpf.attach_uprobe(name="/lib/x86_64-linux-gnu/libc.so.6", sym="pthread_mutex_lock", fn_name="probe_mutex_lock")
    bpf.attach_uprobe(name="/lib/x86_64-linux-gnu/libc.so.6", sym="pthread_mutex_unlock", fn_name="probe_mutex_unlock")



def print_to_file(print_str, f):
    f.write(print_str)

def print_frame(addr, f):
    symbol = b.sym(addr, -1, True)
    print_to_file("\t\t%16s (%x)" % (symbol, addr), f)

def print_stack(stacks, stack_id, f):
    for addr in stacks.walk(stack_id):
        print_frame( addr, f)

def print_init_data(signal, frame):
	global output_file
	global output_file_no
	if output_to_stdout:
		print("Dumping data to stdout\n")
	else:
		print("Dumping data to file %s\n" % (output_file + str(output_file_no)))

	if output_to_stdout:
		f = open(output_file, "w")
	else:
		f = open(str(output_file + str(output_file_no)), "w")

	if not output_to_stdout:
		output_file_no = output_file_no + 1

	pids = []
	for items in lists:
		if items[2] not in pids:
			pids.append(items[2])
	sorted_by_pid = sorted(lock_stacks.items(), key = lambda lock_stacks: (lock_stacks[1].pid))
	locks_by_pid = itertools.groupby(sorted_by_pid, lambda lock_stacks: (lock_stacks[1].pid))

	for k, v in locks_by_pid:
		print_to_file("For pid %d\n" % (k), f)
		for i in sorted(v, key = lambda v: v[0].value):
			print_to_file("At time %d, for mutex %d\n" % (i[0].value, i[1].mtx), f)
			#print("At time %d, for mutex %d\n" % (i[0].value, i[1].mtx))
			# syms = b.get_user_functions(pid=k)
			print_stack(stacks, i[1].stack_id, f)
			print_to_file("\n", f)

	sys.exit(0)

task_to_track = sys.argv[1]
# PID = sys.argv[1]
output_to_stdout = 0

if len(sys.argv) == 3:
	output_file = str(sys.argv[2]) + "."
else:
	output_to_stdout = 1
	output_file = "/dev/stdout"

output_file_no = 1
lists = []
# load BPF program
try:
    b = BPF(text=prog)
except Exception as e:
    print(f"Failed to compile BPF program: {e}")
    exit(1)

attach(b)

lock_stacks = b["lock_stacks"]
stacks = b["stacks"]

#signal.signal(signal.SIGTERM, print_init_data)
signal.signal(signal.SIGINT, print_init_data)

while True:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
		# print(f"Task: {task}, PID: {pid}, CPU: {cpu}, Flags: {flags}, Timestamp: {ts}, Message: {msg}")
    except ValueError:
        continue
    if task_to_track in task.decode('utf-8', 'replace'):
	    lists.append([ts, task, pid])
		

