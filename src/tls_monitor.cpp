#include <unistd.h>
#include <fstream>
#include <iostream>
#include <exception>
#include <assert.h>

#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <fmt/core.h>

#include <bcc_version.h>
#include <BPF.h>

// inline bpf code
#include "bpf/tls_monitor.h"

/*

Note : TLS connection patterns:
----------------------------------------
| byte # | Value   | Description       |
----------------------------------------
| 0      | 22      | TLS id            |
----------------------------------------
| 1      | 3/2/1/0 | Minor TLS version |
----------------------------------------
| 2      | 1       | Major TLS version |
----------------------------------------

*/

struct attach_probe_t final
{
    attach_probe_t(ebpf::BPF &ebpf,
                   std::string fnname,
                   std::string probe_name,
                   bpf_probe_attach_type type = BPF_PROBE_ENTRY)
        : _ebpf(ebpf), _fnname(std::move(fnname)), _probe_name(std::move(probe_name))
    {
        std::cout << "Attaching probe=[" << _probe_name << "] to fnname=[" << _fnname << "]\n";
        auto rc = ebpf.attach_kprobe(_fnname, _probe_name, 0, type, 0);
        if (rc.code() != 0)
        {
            std::cerr << rc.msg() << std::endl;
            throw std::runtime_error("failed to attach probe [" + _probe_name + "]");
        }
    }

    ~attach_probe_t()
    {
        try
        {
            auto rc = _ebpf.detach_kprobe(_fnname);
            if (rc.code() != 0)
                std::cerr << "error :" << rc.msg() << std::endl;
        }
        catch (const std::exception &e)
        {
            std::cerr << e.what() << '\n';
        }
    }

private:
    ebpf::BPF &_ebpf;
    std::string _fnname;
    std::string _probe_name;
};

struct startup_t final
{
    startup_t(int argc, char **argv)
    {
        if (argc != 2)
        {
            std::cerr << argv[0] << "Usage: tls_monitor <pid>" << std::endl;
            exit(EXIT_FAILURE);
        }

        // handle passed arguments
        try
        {
            _pid = std::stoul(argv[1]);
            assert(_pid != 0U);

            check_pid();
        }
        catch (const std::exception &ex)
        {
            std::cerr << "Error: expected <pid>, but [" << argv[1] << "] provided.\n";
            exit(EXIT_FAILURE);
        }
   }

    const unsigned long pid() const
    {
        return _pid;
    }

private:
    void check_pid()
    {
        if( 0 != kill((pid_t)_pid, 0))
        {
            std::cerr << "Error: process with pid [" << _pid << "] not found.\n";
            exit(EXIT_FAILURE);
        }
    }

    unsigned long _pid{0};
};

struct accept_event_t
{
    struct sockaddr addr;
};

void on_tls_event_handler(void *cb_cookie, void *data, int data_size)
{
    auto event = static_cast<accept_event_t *>(data);
    struct sockaddr_in *peer = (struct sockaddr_in *)&event->addr;
    std::cout << fmt::format("address=[{}], port=[{}]\n", inet_ntoa(peer->sin_addr), ntohs(peer->sin_port));
}

int main(int argc, char *argv[])
{
    startup_t startup(argc, argv);

    ebpf::BPF bpf;
    auto init_res = bpf.init(BPF_PROGRAM);
    if (init_res.code() != 0)
    {
        std::cerr << init_res.msg() << std::endl;
        exit(EXIT_FAILURE);
    }

    // set filterting pid
    uint32_t key{0};
    auto pid_table = bpf.get_array_table<uint32_t>("target_pid");
    auto rc = pid_table.update_value(key, startup.pid());
    if (rc.code() != 0)
    {
        std::cerr << rc.msg() << std::endl;
        exit(EXIT_FAILURE);
    }
    else
    {
        std::cout << "started for pid [" << startup.pid() << "]\n";
    }

    // read
    auto syscall_read_name = bpf.get_syscall_fnname("read");
    attach_probe_t read_enter(bpf, syscall_read_name, "syscall__read_enter");
    attach_probe_t read_exit(bpf, syscall_read_name, "syscall__read_exit", BPF_PROBE_RETURN);

    //socket
    auto syscall_socket_name = bpf.get_syscall_fnname("socket");
    attach_probe_t socket_enter(bpf, syscall_socket_name, "syscall__socket_enter");
    attach_probe_t socket_exit(bpf, syscall_socket_name, "syscall__socket_exit", BPF_PROBE_RETURN);

    //close
    auto syscall_close_name = bpf.get_syscall_fnname("close");
    attach_probe_t close_enter(bpf, syscall_close_name, "syscall__close_enter");

    //accept
    auto syscall_accept_name = bpf.get_syscall_fnname("accept");
    attach_probe_t accept_enter(bpf, syscall_accept_name, "syscall__accept_enter");
    attach_probe_t accept_exit(bpf, syscall_accept_name, "syscall__accept_exit", BPF_PROBE_RETURN);

    rc = bpf.open_perf_buffer("tls_events", &on_tls_event_handler);
    if (rc.code() != 0)
    {
        std::cerr << rc.msg() << "\n";
        return EXIT_FAILURE;
    }

    std::ifstream pipe("/sys/kernel/debug/tracing/trace_pipe");
    while (true)
    {
#if 0
        std::string line;
        if (std::getline(pipe, line))
        {
            std::cout << "bpf log : [" << line << "]\n";
        }
#else
        bpf.poll_perf_buffer("tls_events");
#endif
    }

    return 0;
}

#if 0
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



const std::string BPF_PROGRAM = R"(
#include <linux/fs.h>
#include <linux/socket.h>
#include <net/inet_sock.h>
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
  u8 u0;
  u8 u1;
  u8 u2;
};
BPF_PERF_OUTPUT(events);

// store msghdr pointer captured on syscall entry to parse on syscall return
BPF_HASH(tbl_tcp_msghdr, u64, struct msghdr *);
BPF_HASH(tbl_tcp_sock, u64, struct sock *);

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

int kprobe__tcp_recvmsg(struct pt_regs *ctx)
{
    if(!match_target_pid())
        goto CLEANUP;

    __u64 pid_tgid = bpf_get_current_pid_tgid();

    struct msghdr *msghdr = (struct msghdr *)PT_REGS_PARM2(ctx);
    if (msghdr == 0)
        goto CLEANUP;
    tbl_tcp_msghdr.update(&pid_tgid, &msghdr);

    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (sk == 0)
        goto CLEANUP;
    tbl_tcp_sock.update(&pid_tgid, &sk);

CLEANUP:
    return 0;
}

int kretprobe__tcp_recvmsg(struct pt_regs *ctx)
{
    if(!match_target_pid())
        goto EXIT;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct msghdr **msgpp = tbl_tcp_msghdr.lookup(&pid_tgid);
    if (msgpp == 0)
        goto CLEANUP;

    struct msghdr *msghdr = (struct msghdr *)*msgpp;
    if (msghdr->msg_iter.type != ITER_IOVEC)
        goto CLEANUP;

    int copied = (int)PT_REGS_RC(ctx);
    if (copied < 0)
        goto CLEANUP;

    size_t buflen = (size_t)copied;
    if (buflen > msghdr->msg_iter.iov->iov_len)
        goto CLEANUP;

    // filter out SSL connection
    u8 payload[3];
    void *iovbase = msghdr->msg_iter.iov->iov_base;
    bpf_probe_read(&payload, 3, iovbase);

    if(payload[0] != 0x16 || payload[1] != 0x03)
    {
        // not ssl/tls connection
        //goto CLEANUP;
    }

    struct sock **skp = tbl_tcp_sock.lookup(&pid_tgid);
    if(skp == 0)
        goto CLEANUP;

    struct sock *sk = (struct sock *)*skp;

    struct event_t event = {};
    process_sk(sk, &event);
    event.is_recv = 1;
    event.u0 = payload[0];
    event.u1 = payload[1];
    event.u2 = payload[2];
    event.len = copied;
    event.tls_version = payload[2];

    events.perf_submit(ctx, &event, sizeof(event));

CLEANUP:
    tbl_tcp_msghdr.delete(&pid_tgid);
    tbl_tcp_sock.delete(&pid_tgid);

EXIT:
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
    uint8_t u0;
    uint8_t u1;
    uint8_t u2;
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
              << "], payload=[" << fmt::format("{:02x} {:02x} {:02x}", event->u0, event->u1, event->u2)
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

    // attach tcp_recvmsg
    rc = bpf.attach_kprobe("tcp_recvmsg", "kprobe__tcp_recvmsg");
    if (rc.code() != 0)
    {
        std::cerr << rc.msg() << "\n";
        return EXIT_FAILURE;
    }
    rc = bpf.attach_kprobe("tcp_recvmsg", "kretprobe__tcp_recvmsg", 0 , BPF_PROBE_RETURN, 0);
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
#endif