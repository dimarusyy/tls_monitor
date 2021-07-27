#!/usr/bin/python
#
# sslsniff  Captures data on read/recv or write/send functions of libc,
#           For Linux, uses BCC, eBPF.
#
# USAGE: tls_monitor.py [-p PID] [-d] [--hexdump]
#

from __future__ import print_function
from bcc import BPF
from bcc.utils import printb
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack
import ctypes as ct
import argparse
import sys
from time import strftime

# arguments
examples = """examples:
    ./tls_monitor -p 181       # monitor PID 181 only
"""
parser = argparse.ArgumentParser(
    description="Sniff TLS connection",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-p", "--pid", type=int, help="sniff this PID only.")
parser.add_argument("--ebpf", action="store_true",
                    help=argparse.SUPPRESS)
parser.add_argument("--hexdump", action="store_true", dest="hexdump",
                    help="show data as hexdump instead of trying to decode it as UTF-8")
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

struct read_event_t
{
    unsigned int fd;
    unsigned int count;
};
BPF_PERF_OUTPUT(read_events);

int syscall__read_enter(struct pt_regs *ctx,
                   unsigned int fd, char __user *buf, size_t count)
{
    if(!match_target_pid())
        goto EXIT;

    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct read_event_t event = {};
    event.fd = fd;
    event.count = count;

    read_events.perf_submit(ctx, &event, sizeof(event));

    bpf_trace_printk("syscall__read_enter(): fd=[%d], buf=[%d], count=[%d]\\n", fd, buf, count);
EXIT:
    return 0;
}

int syscall__socket_enter(struct pt_regs *ctx,
                        int domain, int type, int protocol)
{
    if(!match_target_pid())
        goto EXIT;

    bpf_trace_printk("syscall__socket_enter(): domain=[%d], type=[%d], protocol=[%d]\\n", domain, type, protocol);

EXIT:
    return 0;
}

int syscall__socket_exit(struct pt_regs *ctx)
{
    if(!match_target_pid())
        goto EXIT;

    int sockfd = (int) PT_REGS_RC(ctx);;

    bpf_trace_printk("syscall__socket_exit(): sockfd=[%d]\\n", sockfd);

EXIT:
    return 0;
}

//
struct accept_event_t
{
    unsigned int sockfd;
    u32 addr[4];
};
BPF_PERF_OUTPUT(accept_events);

BPF_HASH(accept_table, u64, struct sockaddr *);
//

int syscall__accept_enter(struct pt_regs *ctx,
                  int sockfd, struct sockaddr *addr, unsigned int *addrlen)
{
    if(!match_target_pid())
        goto EXIT;

    bpf_trace_printk("syscall__accept_enter(): sockfd=[%d]\\n", sockfd);

    u64 pid_tgid = bpf_get_current_pid_tgid();
    accept_table.update(&pid_tgid, &addr);

EXIT:
    return 0;
}

int syscall__accept_exit(struct pt_regs *ctx)
{
    if(!match_target_pid())
        goto EXIT;

    int sockfd = (int) PT_REGS_RC(ctx);
    bpf_trace_printk("syscall__accept_exit(): sockfd=[%d]\\n", sockfd);

    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sockaddr** addrp = accept_table.lookup(&pid_tgid);
    if(!addrp)
        goto EXIT;

    struct sockaddr* addr = (struct sockaddr*)*addrp;

    struct accept_event_t event = {};
    event.sockfd = sockfd;
    if(addr->sa_family == AF_INET)
    {
        struct sockaddr_in *sa = (struct sockaddr_in*) addr;
        event.addr[0] = sa->sin_addr.s_addr;
    }
    else
    {
        struct sockaddr_in6 *sa = (struct sockaddr_in6*) addr;
        bpf_probe_read_kernel(event.addr, sizeof(event.addr), &sa->sin6_addr);
    }

    // submit event
    accept_events.perf_submit(ctx, &event, sizeof(event));

EXIT:
    return 0;
}

int syscall__close_enter(struct pt_regs *ctx,
                  int sockfd)
{
    if(!match_target_pid())
        goto EXIT;

    bpf_trace_printk("syscall__close_enter(): sockfd=[%d]\\n", sockfd);

EXIT:
    return 0;
}

'''


if args.ebpf:
    print(prog)
    exit()

b = BPF(text=prog)

if args.pid:
    target_pid = b.get_table("target_pid")
    target_pid[0] = ct.c_uint32(args.pid)
else:
    exit("<pid> paramter is missing")

# It looks like SSL_read's arguments aren't available in a return probe so you
# need to stash the buffer address in a map on the function entry and read it
# on its exit (Mark Drayton)
#
# b.attach_uprobe(name="c", sym="read", fn_name="probe_read_enter",
#                pid=args.pid or -1)
# b.attach_uretprobe(name="c", sym="read",
#                fn_name="probe_read_exit", pid=args.pid or -1)

# b.attach_uprobe(name="c", sym="recv", fn_name="probe_recv_enter",
#                pid=args.pid or -1)

read_fnname = b.get_syscall_fnname("read")
b.attach_kprobe(event=read_fnname, fn_name="syscall__read_enter")

socket_fnname = b.get_syscall_fnname("socket")
b.attach_kprobe(event=socket_fnname, fn_name="syscall__socket_enter")
b.attach_kretprobe(event=socket_fnname, fn_name="syscall__socket_exit")

accept_fnname = b.get_syscall_fnname("accept")
b.attach_kprobe(event=accept_fnname, fn_name="syscall__accept_enter")
b.attach_kretprobe(event=accept_fnname, fn_name="syscall__accept_exit")

clone_fnname = b.get_syscall_fnname("close")
b.attach_kprobe(event=clone_fnname, fn_name="syscall__close_enter")

# header
print("started...\n")

# process events
def print_read_event(cpu, data, size):
    event = b["read_events"].event(data)
    fmt = "READ EVENT : %-12x %-18d\n"
    print(fmt % (event.fd, event.count))

def print_tcp_recvmsg_event(cpu, data, size):
    event = b["tcp_recvmsg_events"].event(data)
    print(" TCP RECVMSG EVENT : %-12d" % (event.len))

# main
#b["read_events"].open_perf_buffer(print_read_event)

# format output
while 1:
    try:
        b.trace_print()
    except KeyboardInterrupt:
        sys.exit(0)

#while 1:
#    try:
#        b.perf_buffer_poll()
#    except KeyboardInterrupt:
#        exit()
