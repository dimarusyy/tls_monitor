/*
 * Copyright (c) Facebook, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License")
 */

#include <signal.h>
#include <unistd.h>
#include <iostream>
#include <sstream>
#include <fstream>
#include <string>
#include <functional>
#include <assert.h>

#include <fmt/core.h>

#include <bcc_version.h>
#include <BPF.h>

/*

Note : TLS connection patterns:
----------------------------------------
| byte # | Value   | Description       |
----------------------------------------
| 0      | 22      | TLS id            |
----------------------------------------
| 1      | 3       | Major TLS version |
----------------------------------------
| 2      | 1/2/3   | Minor TLS version |
----------------------------------------

*/

const std::string BPF_PROGRAM = R"(
#include <linux/fs.h>
#include <linux/socket.h>
#include <net/sock.h>
#include <asm/errno.h>
#include <uapi/linux/ptrace.h>

struct event_t {
  u32 saddr;
  u32 daddr;
  u16 dport;
  u8  v6_saddr[16];
  u8  v6_daddr[16];
  u8  tls_version;
  u8  is_recv;
  u32 len;
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

static void process_sk(struct sock* sk, struct event_t* event)
{
   	bpf_probe_read(&event->saddr, sizeof(event->saddr), &sk->sk_rcv_saddr);
	bpf_probe_read(&event->daddr, sizeof(event->daddr), &sk->sk_daddr);

	bpf_probe_read(&event->v6_saddr, sizeof(event->v6_saddr), &sk->sk_v6_rcv_saddr);
	bpf_probe_read(&event->v6_daddr, sizeof(event->v6_daddr), &sk->sk_v6_daddr);

	bpf_probe_read(&event->dport, sizeof(event->dport), &sk->sk_dport);
    event->dport = ntohs(event->dport);
}

int on_tcp_send(struct pt_regs *ctx,
                struct sock *sk,
                struct msghdr *msg,
                size_t size)
{

    if(!match_target_pid())
        return 0;

    struct event_t event = {};
    event.is_recv = 0;
    process_sk(sk, &event);
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
    if(!match_target_pid())
        return 0;

    //if(len < 3)
    //    return 0;

    // filter out SSL connection
    u8 payload[3];
    //copy_to_iter(&payload, 3, &msg->msg_iter);

    if(payload[0] != 0x16 || payload[1] != 0x03)
    {
        // not ssl/tls connection
        //return 0;
    }

	struct event_t event = {};
    event.is_recv = 1;
    event.len = len;
    process_sk(sk, &event);
    event.tls_version = payload[2];

    events.perf_submit(ctx, &event, sizeof(event));

    return 0;
}

)";

std::string ipv4_to_string(uint32_t ip)
{
    return fmt::format("{}.{}.{}.{}",
                       ((ip)&0xFF),
                       ((ip >> 8) & 0xFF),
                       ((ip >> 16) & 0xFF),
                       ((ip >> 24) & 0xFF));
}

std::string ipv4_to_string(uint8_t (*addr)[16])
{
    return fmt::format(
        "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
        *(addr[0]),
        *(addr[1]),
        *(addr[2]),
        *(addr[3]),
        *(addr[4]),
        *(addr[5]),
        *(addr[6]),
        *(addr[7]),
        *(addr[8]),
        *(addr[9]),
        *(addr[10]),
        *(addr[11]),
        *(addr[12]),
        *(addr[13]),
        *(addr[14]),
        *(addr[15])
    );
}

std::function<void(int)> shutdown_handler;

void on_sigint_handler(int signum)
{
    shutdown_handler(signum);
}

struct event_t
{
    uint32_t saddr;
    uint32_t daddr;
    uint16_t dport;
    uint8_t v6_saddr[16];
    uint8_t v6_daddr[16];
    uint8_t tls_version;
    uint8_t is_recv;
    uint32_t len;
};

void on_event_handler(void *cb_cookie, void *data, int data_size)
{
    auto event = static_cast<event_t *>(data);
    std::cout << "daddr=[" << ipv4_to_string(event->daddr)
              << "], saddr=[" << ipv4_to_string(event->saddr)
              << "], dport=[" << event->dport
              << "], v6_saddr=[" << ipv4_to_string(&event->v6_saddr)
              << "], v6_saddr=[" << ipv4_to_string(&event->v6_saddr)
              << "], tls_version=[" << static_cast<int>(event->tls_version)
              << "], is_recv=[" << static_cast<int>(event->is_recv)
              << "], len=[" << event->len
              << "]\n";
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
        std::cerr << "Error: expected <pid>, but [" << argv[1] << "] provided.\n";
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
