/*
 * Copyright (c) Facebook, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License")
 */

#include <signal.h>
#include <unistd.h>
#include <iostream>
#include <string>
#include <functional>
#include <assert.h>

#include "bcc_version.h"
#include "BPF.h"

/*

Note : TLS connection patterns:
----------------------------------------
| byte # | Value   | Description       |
----------------------------------------
| 0      | 22      | TLS id            |
----------------------------------------
| 1      | 3/2/1   | Minor TLS version |
----------------------------------------
| 2      | 1       | Major TLS version |
----------------------------------------

*/

const std::string BPF_PROGRAM = R"(
#include <linux/fs.h>
#include <linux/socket.h>
#include <asm/errno.h>

struct event_t {
  char ip[4];
  size_t size;
};
BPF_PERF_OUTPUT(events);

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

int on_tcp_send(struct pt_regs *ctx,
                struct sock *sk,
                struct msghdr *msg,
                size_t size)
{
    struct event_t event = {};

    if(!match_target_pid())
        return 0;
    event.ip[0] = 'A';
    event.ip[1] = 'B';
    event.ip[2] = 'C';
    event.ip[3] = 'D';
    event.size = size;

    events.perf_submit(ctx, &event, sizeof(event));

    return 0;
}

int on_tcp_recv(struct pt_regs *ctx,
                struct sock *sk,
                struct msghdr *msg,
                size_t len,
                int nonblock,
		        int flags,
                int *addr_len)
{
    struct event_t event = {};

    if(!match_target_pid())
        return 0;

    event.ip[0] = 'D';
    event.ip[1] = 'C';
    event.ip[2] = 'B';
    event.ip[3] = 'A';
    event.size = len;

    events.perf_submit(ctx, &event, sizeof(event));

    return 0;
}

)";

std::function<void(int)> shutdown_handler;

void on_sigint_handler(int signum)
{
    shutdown_handler(signum);
}

struct event_t
{
    char ip[4];
    size_t size;
};

void on_event_handler(void *cb_cookie, void *data, int data_size)
{
    auto event = static_cast<event_t *>(data);
    std::cout << event->ip << " size=[" << event->size << "]\n";
}

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        std::cerr << argv[0] << "Usage: tls_monitor <pid>" << std::endl;
        return EXIT_FAILURE;
    }

    // handle passed arguments
    uint32_t pid{0};
    try
    {
        pid = std::stoul(argv[1]);
        assert(pid != 0U);
    }
    catch (const std::exception &ex)
    {
        std::cerr << "Error: expected <pid>, but [" << argv[1] << "] given.\n";
        return EXIT_FAILURE;
    }

    // bpf instance
    ebpf::BPF bpf;
    //

    // load program
    auto rc = bpf.init(BPF_PROGRAM);
    if (rc.code() != 0)
    {
        std::cerr << rc.msg() << "\n";
        return EXIT_FAILURE;
    }

    // set filterting pid
    uint32_t key{0};
    auto pid_table = bpf.get_array_table<uint32_t>("target_pid");
    rc = pid_table.update_value(key, pid);
    if (rc.code() != 0)
    {
        std::cerr << rc.msg() << std::endl;
        return 1;
    }

    // attach tcp_sendmsg
    rc = bpf.attach_kprobe("tcp_sendmsg", "on_tcp_send");
    if (rc.code() != 0)
    {
        std::cerr << rc.msg() << "\n";
        return EXIT_FAILURE;
    }

    // attach tcp_sendmsg
    rc = bpf.attach_kprobe("tcp_recvmsg", "on_tcp_recv");
    if (rc.code() != 0)
    {
        std::cerr << rc.msg() << "\n";
        return EXIT_FAILURE;
    }

    rc = bpf.open_perf_buffer("events", &on_event_handler);
    if (rc.code() != 0)
    {
        std::cerr << rc.msg() << "\n";
        return EXIT_FAILURE;
    }

    shutdown_handler = [&](int signum)
    {
        auto rc = bpf.detach_kprobe("tcp_sendmsg");
        if (rc.code() != 0)
        {
            std::cerr << rc.msg() << "\n";
            exit(1);
        }

        rc = bpf.detach_kprobe("tcp_recvmsg");
        if (rc.code() != 0)
        {
            std::cerr << rc.msg() << "\n";
            exit(1);
        }

        exit(0);
    };

    // wait fo Ctrl+C
    signal(SIGINT, on_sigint_handler);

    while (true)
        bpf.poll_perf_buffer("events");

    return EXIT_SUCCESS;
}
