#!/usr/bin/env python
from bcc import BPF
import argparse

# Argument parsing to get the PID of the target process
parser = argparse.ArgumentParser(description="Trace mutex lock/unlock for a specific PID")
parser.add_argument("pid", type=int, help="PID of the process to trace")
args = parser.parse_args()
target_pid = args.pid

# BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/mutex.h>

BPF_HASH(start, u32);

int trace_mutex_lock(struct pt_regs *ctx, struct mutex *lock) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == TARGET_PID) {
        u64 ts = bpf_ktime_get_ns();
        start.update(&pid, &ts);
        bpf_trace_printk("PID %d acquired a mutex\\n", pid);
    }
    return 0;
}

int trace_mutex_unlock(struct pt_regs *ctx, struct mutex *lock) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 *tsp, delta;

    if (pid == TARGET_PID) {
        tsp = start.lookup(&pid);
        if (tsp != 0) {
            delta = bpf_ktime_get_ns() - *tsp;
            bpf_trace_printk("PID %d released a mutex after %llu ns\\n", pid, delta);
            start.delete(&pid);
        }
    }
    return 0;
}
"""


bpf_text = bpf_text.replace("TARGET_PID", str(target_pid))

b = BPF(text=bpf_text)


b.attach_kprobe(event="mutex_lock", fn_name="trace_mutex_lock")
b.attach_kprobe(event="mutex_unlock", fn_name="trace_mutex_unlock")

# print(f"Tracing mutex lock/unlock for PID {target_pid}... Press Ctrl+C to exit.")

while True:
    try:
        b.trace_print()
    except KeyboardInterrupt:
        exit()
