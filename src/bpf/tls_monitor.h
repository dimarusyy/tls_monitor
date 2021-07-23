#include <string>

const std::string BPF_PROGRAM = R"(
#include <linux/ptrace.h>
#include <linux/socket.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <uapi/linux/ptrace.h>

///////////////////////////////////////////////////////////////////////////////////////////

BPF_ARRAY(target_pid, u32, 1);

struct client_hello_t
{
    u32 addr[4];

    // parse header
    int is_tls_header;
    int is_client_record_header;

    // parse handshake
    int is_tls_handshake;
    int is_client_handshake_header;

    // is notified
    int is_notified;
};

BPF_HASH(tls_table, u32 /*socket*/, struct client_hello_t);

BPF_HASH(accept_table, u64, struct sockaddr *);

struct read_args_t
{
    char* buf;
    unsigned int fd;
};
BPF_HASH(read_table, u64, struct read_args_t);

struct tls_event_t
{
    u32 addr[4];
};

BPF_PERF_OUTPUT(tls_events);

///////////////////////////////////////////////////////////////////////////////////////////

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

int syscall__read_enter(struct pt_regs *ctx,
                        unsigned int fd, char __user *buf, size_t count)
{
    if (!match_target_pid())
        return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct read_args_t args = {};
    args.buf = buf;
    args.fd = fd;

    read_table.update(&pid_tgid, &args);

    return 0;
}

int syscall__read_exit(struct pt_regs *ctx)
{
    if (!match_target_pid())
        return 0;

    int count = (int)PT_REGS_RC(ctx);
    bpf_trace_printk("syscall__read_exit(): count=[%d]\n", count);

    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct read_args_t *args = read_table.lookup(&pid_tgid);
    if(!args)
        return 0;

    char *buf = args->buf;
    unsigned int fd = args->fd;

    struct client_hello_t *data = (struct client_hello_t *)tls_table.lookup(&fd);
    if(!data)
    {
        read_table.delete(&pid_tgid);
        return 0;
    }

    // is it TLS ?
    if (count == 5)
    {
        //
        // https://tls.ulfheim.net/
        //
        // parse record header if not parsed before
        if(data->is_tls_header == 0)
        {
            data->is_tls_header = -1;
            data->is_client_record_header = -1;

            // maybe client hello ?
            if(buf[0] == 0x16 && buf[1] == 0x03 && buf[2] == 0x01) //tls 1.x ?
            {
                data->is_tls_header = 1;
                data->is_client_record_header = 1;
            }
        }
    }
    else if (count >= 5 && data->is_tls_header == 1)
    {
        data->is_tls_handshake = -1;
        data->is_client_handshake_header = -1;

        //parse client handshake header
        if(buf[0] == 0x01)
        {
            data->is_tls_handshake = 1;
            data->is_client_handshake_header = 1;
        }
    }

    if(data->is_tls_header == 1 && data->is_tls_handshake == 1 && data->is_notified == 0)
    {
        //submit event
        struct tls_event_t event = {};
        __builtin_memcpy(&event.addr, &data->addr, sizeof(event.addr));
        tls_events.perf_submit(ctx, &event, sizeof(event));

        data->is_notified = 1;
        bpf_trace_printk("syscall__read_exit() detected tls handshake\n");
    }

    bpf_trace_printk("syscall__read_exit(): fd=[%d], buf=[%d], count=[%d]\n", fd, buf, count);

    read_table.delete(&pid_tgid);
    return 0;
}

int syscall__socket_enter(struct pt_regs *ctx,
                          int domain, int type, int protocol)
{
    if (!match_target_pid())
        return 0;

    bpf_trace_printk("syscall__socket_enter(): domain=[%d], type=[%d], protocol=[%d]\n", domain, type, protocol);

    return 0;
}

int syscall__socket_exit(struct pt_regs *ctx)
{
    if (!match_target_pid())
        return 0;

    int sockfd = (int)PT_REGS_RC(ctx);
    ;

    bpf_trace_printk("syscall__socket_exit(): sockfd=[%d]\n", sockfd);

    return 0;
}

int syscall__accept_enter(struct pt_regs *ctx,
                          int sockfd, struct sockaddr *addr, unsigned int *addrlen)
{
    if (!match_target_pid())
        return 0;

    bpf_trace_printk("syscall__accept_enter(): sockfd=[%d]\n", sockfd);
    bpf_trace_printk("syscall__accept_enter(): addr->sa_data[0]=[%d]\n", addr->sa_data[0]);
    bpf_trace_printk("syscall__accept_enter(): addr->sa_data[1]=[%d]\n", addr->sa_data[1]);
    bpf_trace_printk("syscall__accept_enter(): addr->sa_data[2]=[%d]\n", addr->sa_data[2]);
    bpf_trace_printk("syscall__accept_enter(): addr->sa_data[3]=[%d]\n", addr->sa_data[3]);

    u64 pid_tgid = bpf_get_current_pid_tgid();
    accept_table.update(&pid_tgid, &addr);

    return 0;
}

int syscall__accept_exit(struct pt_regs *ctx)
{
    if (!match_target_pid())
        return 0;

    int sockfd = (int)PT_REGS_RC(ctx);
    bpf_trace_printk("syscall__accept_exit(): sockfd=[%d]\n", sockfd);

    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sockaddr **addrp = accept_table.lookup(&pid_tgid);
    if (!addrp)
        return 0;

    struct sockaddr *addr = (struct sockaddr *)*addrp;

    struct client_hello_t data = {};
    data.is_tls_header = 0;
    data.is_client_record_header = 0;
    data.is_tls_handshake = 0;
    data.is_client_handshake_header = 0;
    data.is_notified = 0;

    bpf_trace_printk("syscall__accept_exit(): sa_family=[%d]\n", addr->sa_family);

    if (addr->sa_family == AF_INET)
    {
        struct sockaddr_in *sa = (struct sockaddr_in *)addr;
        data.addr[0] = sa->sin_addr.s_addr;

        bpf_trace_printk("syscall__accept_exit(): addr=[%d]\n", sa->sin_addr.s_addr);
    }
    else
    {
        struct sockaddr_in6 *sa = (struct sockaddr_in6 *)addr;
        bpf_probe_read_kernel(data.addr, sizeof(data.addr), &sa->sin6_addr);
    }

    // update tls_table with the new socket entry and it's address
    struct client_hello_t *existing_client_hello = tls_table.lookup(&sockfd);
    if (existing_client_hello)
    {
        // missing cleanup ?
        tls_table.delete(&sockfd);
    }

    // update hashtable
    tls_table.update(&sockfd, &data);

    // cleanup accept_table
    accept_table.delete(&pid_tgid);

    return 0;
}

int syscall__close_enter(struct pt_regs *ctx,
                         int sockfd)
{
    if (!match_target_pid())
        goto EXIT;

    // delete socket <-> address entry
    tls_table.delete(&sockfd);

    bpf_trace_printk("syscall__close_enter(): sockfd=[%d]\n", sockfd);

EXIT:
    return 0;
}

)";