#!/usr/bin/python3  
from bcc import BPF

program = r"""
BPF_PERF_OUTPUT(counter_table); 
 
struct data_t {     
   int pid;
   int uid;
   char command[16];
};


int hello(void *ctx) {
   struct data_t data = {}; 
 
   data.pid = bpf_get_current_pid_tgid() >> 32;
   data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
   
   bpf_get_current_comm(&data.command, sizeof(data.command));
   
   counter_table.perf_submit(ctx, &data, sizeof(data)); 
 
   return 0;
}
"""

b = BPF(text=program, cflags=["-Wno-macro-redefined"]) 
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello")
 
def print_event(cpu, data, size):  
   data = b["counter_table"].event(data)
   print(f"{data.pid} {data.uid} {data.command.decode()}")
 
b["counter_table"].open_perf_buffer(print_event) 
while True:   
   b.perf_buffer_poll()