#!/usr/bin/python3  
from bcc import BPF
from time import sleep

program = r"""
BPF_HASH(counter_table);

RAW_TRACEPOINT_PROBE(sys_enter)
{
   u64 opcode;
   u64 counter = 0;
   u64 *p;
   
   opcode = ctx->args[1];

   p = counter_table.lookup(&opcode);
   if (p != 0) {
      counter = *p;
   }
   counter++;
   counter_table.update(&opcode, &counter);
   return 0;
}
"""

b = BPF(text=program)

# Attach to a tracepoint that gets hit for all syscalls 
# b.attach_raw_tracepoint(tp="sys_enter", fn_name="hello")

while True:
    sleep(2)
    s = ""
    s += "\n{"
    for k,v in b["counter_table"].items():
        s += f"{k.value}: {v.value}, "
    s += "}"
    print(s)
