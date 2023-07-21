#!/usr/bin/python3
from bcc import BPF

program = r"""
#include <linux/sched.h>

int hello(void *ctx) {
    
    int pid = bpf_get_current_pid_tgid() >> 32;
    int uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    char command[TASK_COMM_LEN];
    bpf_get_current_comm(command, sizeof(command));

    bpf_trace_printk("uid = %d, pid = %d, comm %s", uid, pid, command);

    return 0;
}
"""

b = BPF(text=program, cflags=["-Wno-macro-redefined"])
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello")

b.trace_print()
