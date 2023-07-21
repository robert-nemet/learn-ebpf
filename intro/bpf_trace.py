#!/usr/bin/python3
from bcc import BPF

program = r"""
#include<linux/sched.h>

typedef  struct word_desc {
    char *word;
    int flags;
} WORD_DESC;

typedef struct word_list {
    struct word_list *next;
    WORD_DESC *word;
} WORD_LIST;

int trace(struct pt_regs *ctx) {

    u64 uid;
    uid = bpf_get_current_uid_gid() & 0xFFFFFFFF; 

    WORD_LIST *head, *cur;
    WORD_DESC data;
    
    cur = (void *)PT_REGS_PARM1(ctx);


    bpf_trace_printk("uid = %d, comm %s", uid, *cur->word);

    return 0;
}
"""

b = BPF(text=program, cflags=["-Wno-macro-redefined"])
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="trace")

b.attach_uprobe(name="/bin/bash", sym="caller_builtin", fn_name="trace")

b.trace_print()
