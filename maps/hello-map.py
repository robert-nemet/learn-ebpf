#!/usr/bin/python3  
from bcc import BPF
from time import sleep

program = r"""


struct data_t {
   u64 counter;
   int pid;
   char command[16];
};

BPF_HASH(counter_table, u64, struct data_t);

int hello(void *ctx) {
   struct data_t zero = {};
   struct data_t *val;

   
   u64 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
   int pid = bpf_get_current_pid_tgid() >> 32;

   val = counter_table.lookup_or_try_init(&uid, &zero);
   if (val) {
      val->counter++;
      val->pid = pid;
      bpf_get_current_comm(&val->command, sizeof(val->command));
   }

   return 0;
}
"""

b = BPF(text=program, cflags=["-Wno-macro-redefined"])

syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello")


old_s = ""
while True:
   sleep(2)
   s = ""
   for k,v in b["counter_table"].items():
      s += f"ID {k.value}: cnt: {v.counter} pid: {v.pid} comm: {v.command}\t"
   if s != old_s:
      print(s)
   old_s = s

