import sys
import itertools
from time import sleep
from bcc import BPF
import signal
import ctypes

# Define BPF program
prog = """
#include <linux/ptrace.h>
#include <linux/ktime.h>

struct thread_mutex_key_t {
    u32 tid;
    u64 mtx;
    int lock_stack_id;
};
struct thread_mutex_val_t {
    u64 wait_time_ns;
    u64 lock_time_ns;
    u64 enter_count;
};
struct mutex_timestamp_t {
    u64 mtx;
    u64 timestamp;
};
struct mutex_lock_time_key_t {
    u32 tid;
    u64 mtx;
};
struct mutex_lock_time_val_t {
    u64 timestamp;
    int stack_id;
};

struct mutex_lock_init {
    u32 pid;
    int stack_id;
};

struct futex_lock {
    u64 timestamp;
    u32 __user *futex;
};

struct contention {
    u64 count;
    u64 delta;
};

BPF_HASH(tracing, u32 __user *, struct contention); 
BPF_HASH(start, u32, struct futex_lock); // pid -> futex call start timestamp

// Mutex to the stack id which initialized that mutex
BPF_HASH(init_stacks, u64, struct mutex_lock_init);
// Main info database about mutex and thread pairs
BPF_HASH(locks, struct thread_mutex_key_t, struct thread_mutex_val_t);
// Pid to the mutex address and timestamp of when the wait started
BPF_HASH(lock_start, u32, struct mutex_timestamp_t);
// Pid and mutex address to the timestamp of when the wait ended (mutex acquired) and the stack id
BPF_HASH(lock_end, struct mutex_lock_time_key_t, struct mutex_lock_time_val_t);

// Histogram of wait times
BPF_HISTOGRAM(mutex_wait_hist, u64);
// Histogram of hold times
BPF_HISTOGRAM(mutex_lock_hist, u64);

BPF_STACK_TRACE(stacks, 4096);

int probe_mutex_lock(struct pt_regs *ctx)
{
    u64 now = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid();
    struct mutex_timestamp_t val = {};
    val.mtx = PT_REGS_PARM1(ctx);
    val.timestamp = now;
    lock_start.update(&pid, &val);
    return 0;
}
int probe_mutex_lock_return(struct pt_regs *ctx)
{
    u64 now = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid();
    struct mutex_timestamp_t *entry = lock_start.lookup(&pid);
    if (entry == 0)
        return 0;   // Missed the entry
    u64 wait_time = now - entry->timestamp;
    int stack_id = stacks.get_stackid(ctx, BPF_F_REUSE_STACKID|BPF_F_USER_STACK);
    // If pthread_mutex_lock() returned 0, we have the lock
    if (PT_REGS_RC(ctx) == 0) {
        // Record the lock acquisition timestamp so that we can read it when unlocking
        struct mutex_lock_time_key_t key = {};
        key.mtx = entry->mtx;
        key.tid = pid;
        struct mutex_lock_time_val_t val = {};
        val.timestamp = now;
        val.stack_id = stack_id;
        lock_end.update(&key, &val);
    }
    // Record the wait time for this mutex-tid-stack combination even if locking failed
    struct thread_mutex_key_t tm_key = {};
    tm_key.mtx = entry->mtx;
    tm_key.tid = pid;
    tm_key.lock_stack_id = stack_id;
    struct thread_mutex_val_t *existing_tm_val, new_tm_val = {};
    existing_tm_val = locks.lookup_or_init(&tm_key, &new_tm_val);
    existing_tm_val->wait_time_ns += wait_time;
    if (PT_REGS_RC(ctx) == 0) {
        existing_tm_val->enter_count += 1;
    }
    u64 mtx_slot = bpf_log2l(wait_time / 1000);
    mutex_wait_hist.increment(mtx_slot);
    lock_start.delete(&pid);
    return 0;
}
int probe_mutex_unlock(struct pt_regs *ctx)
{
    u64 now = bpf_ktime_get_ns();
    u64 mtx = PT_REGS_PARM1(ctx);
    u32 pid = bpf_get_current_pid_tgid();
    struct mutex_lock_time_key_t lock_key = {};
    lock_key.mtx = mtx;
    lock_key.tid = pid;
    struct mutex_lock_time_val_t *lock_val = lock_end.lookup(&lock_key);
    if (lock_val == 0)
        return 0;   // Missed the lock of this mutex
    u64 hold_time = now - lock_val->timestamp;
    struct thread_mutex_key_t tm_key = {};
    tm_key.mtx = mtx;
    tm_key.tid = pid;
    tm_key.lock_stack_id = lock_val->stack_id;
    struct thread_mutex_val_t *existing_tm_val = locks.lookup(&tm_key);
    if (existing_tm_val == 0)
        return 0;   // Couldn't find this record
    existing_tm_val->lock_time_ns += hold_time;
    u64 slot = bpf_log2l(hold_time / 1000);
    mutex_lock_hist.increment(slot);
    lock_end.delete(&lock_key);
    return 0;
}
int probe_mutex_init(struct pt_regs *ctx)
{
    u32 pid = bpf_get_current_pid_tgid();
    int stack_id = stacks.get_stackid(ctx, BPF_F_REUSE_STACKID|BPF_F_USER_STACK);
    u64 mutex_addr = PT_REGS_PARM1(ctx);

    struct mutex_lock_init val = {};
    val.pid = pid;
    val.stack_id = stack_id;
    init_stacks.update(&mutex_addr, &val);
    bpf_trace_printk("Pthread mutex init\\n");
    return 0;
}


int trace_futex(struct pt_regs *ctx, u32 __user *uaddr, int op, u32 val, ktime_t
    *timeout, u32 __user *uaddr2, u32 val2)
{
    int FUTEX_WAIT = 0;
    int FUTEX_PRIVATE_FLAG = 128;
    int FUTEX_CLOCK_REALTIME = 256;

    u64 tgid_pid = bpf_get_current_pid_tgid();
    u32 pid = tgid_pid;
    u32 tgid = tgid_pid >> 32;

    if ((op & ~(FUTEX_PRIVATE_FLAG|FUTEX_CLOCK_REALTIME)) != FUTEX_WAIT) 
        return 0;

    u64 ts = bpf_ktime_get_ns();

    struct futex_lock f = {};
    f.timestamp = ts;
    f.futex = uaddr;
    start.update(&pid, &f);
    return 0;
}

int trace_futex_return(struct pt_regs *ctx)
{
    u32 __user *f;
    u32 pid = bpf_get_current_pid_tgid();

    struct futex_lock *val = start.lookup(&pid);

    if (!val) {
        return 0;
    }

    u64 delta = (bpf_ktime_get_ns() - val->timestamp)/1000/1000;

    f = val->futex;

    struct contention *c = tracing.lookup(&f);

    if (!c) {
        struct contention c1 = {};
        c1.delta = delta;
        c1.count = 1;
        tracing.update(&f, &c1);
    }
    else {
        struct contention c2 = {};
        c2.delta = c->delta + delta;
        c2.count = c->count + 1;
        
        tracing.delete(&f);
        tracing.update(&f, &c2);
    }
   
    start.delete(&pid);
    return 0;
}
"""

def attach(bpf):
    bpf.attach_uprobe(name="/lib/x86_64-linux-gnu/libc.so.6", sym="pthread_mutex_init", fn_name="probe_mutex_init")
    bpf.attach_uprobe(name="/lib/x86_64-linux-gnu/libc.so.6", sym="pthread_mutex_lock", fn_name="probe_mutex_lock")
    bpf.attach_uretprobe(name="/lib/x86_64-linux-gnu/libc.so.6", sym="pthread_mutex_lock", fn_name="probe_mutex_lock_return")
    bpf.attach_uprobe(name="/lib/x86_64-linux-gnu/libc.so.6", sym="pthread_mutex_unlock", fn_name="probe_mutex_unlock")
    bpf.attach_kprobe(event="do_futex", fn_name="trace_futex")
    bpf.attach_kretprobe(event="do_futex", fn_name="trace_futex_return")

def print_frame(addr,pid):
    print("\t\t%16s (%x)" % (BPF.sym(addr,pid, True)))

def print_stack(stacks, stack_id, pid):
    for addr in stacks.walk(stack_id):
        print_frame(addr,pid)

def print_init_data(signal, frame):
    pids = []
    for items in lists:
        if items[2] not in pids:
            pids.append(items[2])

    mutex_ids = {}
    next_mutex_id = 1

    print("\n\n\nInit of all locks\n\n\n")

    for k, v in init_stacks.items():
        if v.pid in pids:
            mutex_id = "#%d" % next_mutex_id
            next_mutex_id += 1
            mutex_ids[k.value] = mutex_id
            print("init stack for mutex %x (%s)" % (k.value, mutex_id))
            print_stack( stacks, v.stack_id ,v.pid)
            print("")

    print("\n\n\nPer thread lock analysis\n\n\n")

    grouper = lambda k_v: k_v[0].tid
    sorted_by_thread = sorted(locks.items(), key=grouper)
    locks_by_thread = itertools.groupby(sorted_by_thread, grouper)

    for tid, items in locks_by_thread:
        if tid in pids:
            print("thread %d" % tid)
            for k, v in sorted(items, key=lambda k_v: -k_v[1].wait_time_ns):
                if k.mtx in mutex_ids:
                    mutex_descr = mutex_ids[k.mtx]
                    print("\tFound in mutex_ids. mutex (%s) %x ::: wait time %.2fus ::: hold time %.2fus ::: enter count %d" %
                          (mutex_descr, k.mtx, v.wait_time_ns / 1000.0, v.lock_time_ns / 1000.0, v.enter_count))
                else:
                
                    mutex_descr = syms.decode_addr(k.mtx)
                    print("\tNot found in mutex_ids. mutex (%s) %x ::: wait time %.2fus ::: hold time %.2fus ::: enter count %d" %
                          (mutex_descr, k.mtx, v.wait_time_ns / 1000.0, v.lock_time_ns / 1000.0, v.enter_count))
                print_stack(stacks, k.lock_stack_id, tid)
                print("")

    mutex_wait_hist.print_log2_hist(val_type="wait time (us)")
    mutex_lock_hist.print_log2_hist(val_type="hold time (us)")

    print("\n\n\nOverall per lock analysis\n\n\n")

    mutex_analysis = {}
    sorted_by_thread = sorted(locks.items(), key=grouper)
    locks_by_thread = itertools.groupby(sorted_by_thread, grouper)
    for tid, items in locks_by_thread:
        if tid in pids:
            for k, v in sorted(items, key=lambda k_v: -k_v[1].wait_time_ns):
                if k.mtx in mutex_analysis:
                    mutex_analysis[k.mtx][0] = mutex_analysis[k.mtx][0] + v.wait_time_ns / 1000.0
                    mutex_analysis[k.mtx][1] = mutex_analysis[k.mtx][1] + v.lock_time_ns / 1000.0
                    mutex_analysis[k.mtx][2] = mutex_analysis[k.mtx][2] + v.enter_count
                else:
                    mutex_analysis[k.mtx] = [v.wait_time_ns / 1000.0, v.lock_time_ns / 1000.0, v.enter_count]

    for k in mutex_analysis:
        v = mutex_analysis[k]
        mutex_descr = mutex_ids[k] if k in mutex_ids else 0
        print("\tmutex %x (%s) ::: wait time %.2fus ::: hold time %.2fus ::: enter count %d" %
              (k, mutex_descr, v[0], v[1], v[2]))

    print("\n\n\nContention analysis\n\n\n")

    for k in tracing:
        mutex_descr = mutex_ids[k.value] if k.value in mutex_ids else 0
        print("Mutex %x (%s) Count=%d \n" % (k.value, mutex_descr, tracing[k].count))
    
    sys.exit(0)

task_to_track = sys.argv[1]
print("Task to be tracked is ", task_to_track)
lists = []

try:
    b = BPF(text=prog)
except Exception as e:
    print(f"Failed to compile BPF program: {e}")
    exit(1)

attach(b)

init_stacks = b["init_stacks"]
stacks = b["stacks"]
locks = b["locks"]
mutex_lock_hist = b["mutex_lock_hist"]
mutex_wait_hist = b["mutex_wait_hist"]
tracing = b["tracing"]

# signal.signal(signal.SIGTERM, print_init_data)
signal.signal(signal.SIGINT, print_init_data)

while True:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    except ValueError:
        continue
    if task_to_track in task.decode('utf-8', 'replace'):
        lists.append([ts, task, pid])
