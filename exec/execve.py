#!/usr/bin/python
#from __future__ import print_function
from bcc import BPF
from time import sleep,strftime
import argparse
from bcc.utils import printb

parser= argparse.ArgumentParser()
parser.add_argument("interval", nargs="?",default=99999999,help="output interval, in seconds")
parser.add_argument("counts", nargs="?", default=99999999,help="number of putputs")
args = parser.parse_args()
countdown = int(args.counts)

bpf_text='''
#include <linux/string.g>
#include <linus/sched.h>
#include <uapi/linux/ptrace.h>

struct execve_index_t{
    u32 execve_pid;
    u32 create_cpu;
    u32 execve_comm[TASK_COMM_LEN];
};



'''