#!/usr/bin/python
from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
import argparse
from bcc.utils import printb
from bcc.syscall import syscall_name, syscalls
parser = argparse.ArgumentParser()
parser.add_argument("interval", nargs="?", default=99999999,
                help="output interval, in seconds")
parser.add_argument("counts", nargs="?", default=99999999,
                help="number of putputs")
args = parser.parse_args()
countdown = int(args.counts)

bpf_text="""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct key_t {
    u32 prev_pid;
    u32 current_pid;
    //char prev_cmd[TASK_COMM_LEN];
    char current_cmd[TASK_COMM_LEN];
    u64 start_time;
    u64 end_time;
    //u64 continue_time;
    u32 cpu;
};
struct comp_t {
    u32 sched_start_pid;
    u32 cpu;
};

BPF_HASH(counts,struct key_t);
BPF_HASH(start,struct comp_t);

int sched_start(){
    u32 pid=bpf_get_current_pid_tgid();
    //char cmdline[TASK_COMM_LEN]=bpf_get_current_comm();
    u64 ts=bpf_ktime_get_ns();
    struct comp_t comp_start;

    comp_start.sched_start_pid=pid;
    comp_start.cpu=bpf_get_smp_processor_id();

    start.update(&comp_start,&ts);
    return 0;
}

int sched_end(struct pt_regs *ctx,struct task_struct *prev){
    u64 delta,*tsp,ts;
    ts=bpf_ktime_get_ns();
    u32 prev_pid=prev->pid;
    u32 current_pid=bpf_get_current_pid_tgid();
    u32 cpu=bpf_get_smp_processor_id();
    
    struct key_t data={};

    struct comp_t comp_end;
    comp_end.sched_start_pid=prev_pid;
    comp_end.cpu=cpu;

    //delta=ts-*tsp;

    tsp=start.lookup(&comp_end);
    if(tsp==0)
        return 0;

    delta=ts-*tsp;
    
    data.prev_pid=prev_pid;
    data.current_pid=current_pid;
    //data.prev_cmd=prev->comm;
    //strcmp(data.prev_cmd,prev->pid);
    bpf_get_current_comm(&data.current_cmd,sizeof(data.current_cmd));
    data.start_time=*tsp;
    data.end_time=ts;
    data.cpu=cpu;


    start.delete(&comp_end);
    counts.update(&data,&delta);

    return 0;
}
"""

b=BPF(text=bpf_text)
b.attach_kprobe(event="schedule",fn_name="sched_start")
b.attach_kprobe(event="finish_task_switch",fn_name="sched_end")

print("Tracing run schedule... Hit Ctrl-C to end.")


exiting=0 if args.interval else 1
data=b.get_table("counts")
#print(type(data))
while (1):
    try:
        sleep(int(args.interval))
    except KeyboardInterrupt:
        exiting=1
    for k,v in data.items():
        #print("k:%s"%(type(k)))
        #print("v:%s"%(type(v)))
        print("cpu: %-3d start_pid: %-5d  --->  end_pid: %-5d(curremt_cmd:%-15s)  start_time: %-15d~~~end_time: %-15d   delta: %-7d  "%(k.cpu,k.prev_pid,k.current_pid,k.current_cmd,k.start_time,k.end_time,v.value))
        #print("%-5d" %(v.value))



    data.clear()

    countdown-=1
    if exiting or countdown <=0:
        exit()
