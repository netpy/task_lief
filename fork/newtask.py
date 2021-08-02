#!/usr/bin/python
#from __future__ import print_function
from bcc import BPF
#from time import sleep, strftime
from time import sleep
import argparse
#from bcc.utils import printb
#from bcc.syscall import syscall_name, syscalls
parser = argparse.ArgumentParser()
parser.add_argument("interval", nargs="?", default=99999999,
                help="output interval, in seconds")
parser.add_argument("counts", nargs="?", default=99999999,
                help="number of putputs")
args = parser.parse_args()
countdown = int(args.counts)


bpf_text='''
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/string.h>

struct create_index_t{
    u32 create_pid;
    u32 create_cpu;
    char create_comm[TASK_COMM_LEN];
};

struct create_key_t{
    u32 create_pid;
    u32 create_cpu;
    u64 create_start_time;
    char create_comm[TASK_COMM_LEN];
};

struct create_value_t{
    u64 delta;
    u64 create_finish_time;
    char create_child_comm[TASK_COMM_LEN];
    u64 create_child_pid;
    u32 create_child_cpu;
};


BPF_HASH(create_index,struct create_index_t,u64);
BPF_HASH(create_data,struct create_key_t,struct create_value_t);


int create_start(){
    u32 pid=bpf_get_current_pid_tgid();
    u64 start_time=bpf_ktime_get_ns();
    u32 cpu=bpf_get_smp_processor_id();
    
    struct create_index_t create_start={};

    create_start.create_pid=pid;
    create_start.create_cpu=cpu;
    bpf_get_current_comm(&create_start.create_comm,sizeof(create_start.create_comm));

    create_index.update(&create_start,&start_time);

    return 0;
}


int create_end(struct pt_regs *ctx, struct task_struct *child_task_struct){
    u32 pid=bpf_get_current_pid_tgid();
    
    u64 ts=bpf_ktime_get_ns();
    u32 cpu=bpf_get_smp_processor_id();
    u64 *create_start_time;
    
    struct create_key_t create_end={};
    struct create_index_t create_lookup={};
    struct create_value_t create_child={};

    
    create_lookup.create_pid=pid;
    create_lookup.create_cpu=cpu;
    bpf_get_current_comm(&create_lookup.create_comm,sizeof(create_lookup.create_comm));

    create_start_time=create_index.lookup(&create_lookup);
    if(create_start_time==0)
        return 0;
    
    create_end.create_pid=pid;
    create_end.create_cpu=cpu;
    bpf_get_current_comm(&create_end.create_comm,sizeof(create_end.create_comm));
    create_end.create_start_time=*create_start_time;

    create_child.delta=ts-*create_start_time;
    create_child.create_finish_time=ts;
    create_child.create_child_pid=child_task_struct->pid;
    create_child.create_child_cpu=child_task_struct->wake_cpu;
    //strcpy(create_child.create_child_comm, child_task_struct->comm);
    bpf_probe_read_kernel_str(create_child.create_child_comm, sizeof(create_child.create_child_comm), child_task_struct->comm);

    create_data.update(&create_end,&create_child);

    return 0;
}

'''



b=BPF(text=bpf_text)
b.attach_kprobe(event="_do_fork",fn_name="create_start")
b.attach_kprobe(event="wake_up_new_task",fn_name="create_end")

exiting=0 if args.interval else 1
data=b.get_table("create_data")
#print(type(data))
while (1):
    try:
        sleep(int(args.interval))
    except KeyboardInterrupt:
        exiting=1
    for k,v in data.items():
        #print("k:%s"%(type(k)))
        #print("v:%s"%(type(v)))
        print(" create_pid: %-5d (create_comm:%-15s  create_cpu: %-3d ) --->  child_pid: %-5d(child_comm:%-15s   child_cpu: %-3d )  start_time: %-15d~~~end_time: %-15d   delta: %-7d  "%(k.create_pid,k.create_comm,k.create_cpu,v.create_child_pid,v.create_child_comm,v.create_child_cpu,k.create_start_time,v.create_finish_time,v.delta))
        #print(" create_pid: %-5d (create_comm:%-15s  create_cpu: %-3d ) --->  child_pid: %-5d( child_cpu: %-3d )  start_time: %-15d~~~end_time: %-15d   delta: %-7d  "%(k.create_pid,k.create_comm,k.create_cpu,v.create_child_pid,v.create_child_cpu,k.create_start_time,v.create_finish_time,v.delta))
        #print("%-5d" %(v.value))


    data.clear()

    countdown-=1
    if exiting or countdown <=0:
        exit()