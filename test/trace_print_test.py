from bcc import BPF

bpf_text="""
#include <uapi/linux/ptrace.h>

struct urandom_read_args{
    u64 __unused__;
    u32 got_bits;
    u32 pool_left;
    u32 input_left;
    };

int printarg(struct urandom_read_args * args){
    bpf_trace_printk("%d\\n",args->got_bits);
    return 0;
    };
"""

b=BPF(text=bpf_text)
b.attach_tracepoint("sched:sched_switch","printarg")

while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    except ValueError:
        continue
    print("%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))

