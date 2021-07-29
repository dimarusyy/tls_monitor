#!/usr/bin/python
#
# sslsniff  Captures data on read/recv or write/send functions of libc,
#           For Linux, uses BCC, eBPF.
#
# USAGE: tls_monitor.py [-p PID] [-d] [--hexdump]
#

from bcc import BPF
from bcc.utils import printb
import ctypes as ct
import argparse
import ipaddress
import socket

# arguments
examples = """examples:
    ./tls_monitor -p 181       # monitor PID 181 only
"""
parser = argparse.ArgumentParser(
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-p", "--pid", type=int, help="sniff this PID only.")
args = parser.parse_args()


prog = '''
#include <linux/ptrace.h>
#include <linux/sched.h>        /* For TASK_COMM_LEN */
#include <linux/socket.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <uapi/linux/ptrace.h>

BPF_ARRAY(target_pid, u32, 1);

static bool match_target_pid()
{
    int key = 0, *val, tpid, cpid;

    val = target_pid.lookup(&key);
    if (!val)
        return false;

    tpid = *val;
    cpid = bpf_get_current_pid_tgid() >> 32;

    if (tpid == 0 || tpid != cpid)
        return false;
    return true;
}

struct accept_event_t
{
    unsigned int sin_addr;
    unsigned short sin_port;
};
BPF_PERF_OUTPUT(accept_events);

BPF_HASH(accept_table, u64, struct sockaddr *);

int syscall__accept_enter(struct pt_regs *ctx,
                  int sockfd, struct sockaddr *addr, unsigned int *addrlen)
{
    if(!match_target_pid())
        goto EXIT;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    accept_table.update(&pid_tgid, &addr);

EXIT:
    return 0;
}

int syscall__accept_exit(struct pt_regs *ctx)
{
    if(!match_target_pid())
        goto EXIT;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sockaddr** addrp = accept_table.lookup(&pid_tgid);
    if(!addrp)
        goto EXIT;

    struct sockaddr_in* addr = (struct sockaddr_in*)*addrp;

    struct accept_event_t event = {};
    bpf_probe_read(&event.sin_addr, sizeof(event.sin_addr), &(addr->sin_addr));
    event.sin_port = addr->sin_port;

    // submit event
    accept_events.perf_submit(ctx, &event, sizeof(event));

EXIT:
    return 0;
}

'''

b = BPF(text=prog)

if args.pid:
    target_pid = b.get_table("target_pid")
    target_pid[0] = ct.c_uint32(args.pid)
else:
    exit("<pid> paramter is missing")

accept_fnname = b.get_syscall_fnname("accept")
b.attach_kprobe(event=accept_fnname, fn_name="syscall__accept_enter")
b.attach_kretprobe(event=accept_fnname, fn_name="syscall__accept_exit")

# header
print("started...\n")

# process events
def print_accept_event(cpu, data, size):
    event = b["accept_events"].event(data)
    fmt = "ACCEPT EVENT : %s:%d\n"
    print(fmt % (str(ipaddress.ip_address(event.sin_addr)), socket.ntohs(event.sin_port)))

# main
b["accept_events"].open_perf_buffer(print_accept_event)

# format output
while 1:
   try:
       b.perf_buffer_poll()
   except KeyboardInterrupt:
       exit()
