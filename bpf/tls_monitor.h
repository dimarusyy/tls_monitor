#include <string>

/*

https://tls.ulfheim.net/


TLS connection patterns:
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

const std::string BPF_PROGRAM = R"(
#include <linux/ptrace.h>
#include <linux/socket.h>
#include <net/sock.h>
#include <uapi/linux/ptrace.h>

///////////////////////////////////////////////////////////////////////////////////////////

#define DEBUG 0

#if DEBUG
#define LOG(...) bpf_trace_printk(__VA_ARGS__);
#else
#define LOG(...) ;
#endif

///////////////////////////////////////////////////////////////////////////////////////////


BPF_ARRAY(target_pid, u32, 1);

struct tls_hello_t
{
    struct sockaddr addr;

    // parse header
    int is_tls_header;

    // parse handshake
    int is_tls_handshake;
    int is_client_handshake_header;
    int is_server_handshake_header;
};

//
// Keeps <client_id of socket, tls_hello_t> pairing
// to accumulate read data from the socket
// and process parsing when necessary.
BPF_HASH(socket_table, u32 /*socket*/, struct tls_hello_t);

//
// Keeps <pid_tid, struct sockaddr *> pairing
BPF_HASH(accept_table, u64, struct sockaddr *);

struct connect_args_t
{
    int sockfd;
    struct sockaddr addr;
};
BPF_HASH(connect_table, u64, struct connect_args_t);

struct read_args_t
{
    char *buf;
    unsigned int fd;
};
BPF_HASH(read_table, u64, struct read_args_t);

struct tls_event_t
{
    struct sockaddr addr;
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

///////////////////////////////////////////////////////////////////////////////////////////

static int process_read(struct pt_regs *ctx, char *buf, int count, struct tls_hello_t *data)
{
    //
    // is it TLS ?
    //
    if (count == 5 &&
        data->is_tls_header == 0)
    {
        // read first 5 bytes of hello message
        // parse record header if not parsed before
        data->is_tls_header = -1;

        // maybe client hello ?
        if (buf[0] == 0x16) //tls 1.x ?
        {
            if (buf[1] == 0x03 && buf[2] == 0x01)
            {
                data->is_tls_header = 1;
            }
            if (buf[1] == 0x03 && buf[2] == 0x02)
            {
                data->is_tls_header = 1;
            }
            if (buf[1] == 0x03 && buf[2] == 0x03)
            {
                data->is_tls_header = 1;
            }
        }

        LOG("process_read() #1 : is_tls_header=[%d], is_tls_handshake=[%d]\n", data->is_tls_header, data->is_tls_handshake);
    }
    else if (count >= 6 &&
             data->is_tls_header == 1 &&
             data->is_tls_handshake == 0)
    {
        // read more bytes including Client/Server hello

        data->is_tls_handshake = -1;
        data->is_client_handshake_header = -1;
        data->is_server_handshake_header = -1;

        //parse client handshake header
        if (buf[0] == 0x01)
        {
            if (buf[4] == 0x03 && buf[5] == 0x01)
            {
                data->is_tls_handshake = 1;
                data->is_client_handshake_header = 1;
            }
            if (buf[4] == 0x03 && buf[5] == 0x02)
            {
                data->is_tls_handshake = 1;
                data->is_client_handshake_header = 1;
            }
            if (buf[4] == 0x03 && buf[5] == 0x03)
            {
                data->is_tls_handshake = 1;
                data->is_client_handshake_header = 1;
            }
        }

        //parse serve handshake header
        if (buf[0] == 0x02)
        {
            data->is_tls_handshake = 1;
            if (buf[4] == 0x03 && buf[5] == 0x01)
            {
                data->is_tls_handshake = 1;
                data->is_server_handshake_header = 1;
            }
            if (buf[4] == 0x03 && buf[5] == 0x02)
            {
                data->is_tls_handshake = 1;
                data->is_server_handshake_header = 1;
            }
            if (buf[4] == 0x03 && buf[5] == 0x03)
            {
                data->is_tls_handshake = 1;
                data->is_server_handshake_header = 1;
            }
        }

        LOG("process_read() #2 : is_tls_header=[%d], is_tls_handshake=[%d]\n", data->is_tls_header, data->is_tls_handshake);
    }

    LOG("process_read() : is_tls_header=[%d], is_tls_handshake=[%d]\n", data->is_tls_header, data->is_tls_handshake);

    return data->is_tls_header == 1 && data->is_tls_handshake == 1;
}

static void submit_event(struct pt_regs *ctx, struct tls_hello_t *data)
{
    struct tls_event_t event = {};
    __builtin_memcpy(&event.addr, &data->addr, sizeof(event.addr));
    tls_events.perf_submit(ctx, &event, sizeof(event));
}

///////////////////////////////////////////////////////////////////////////////////////////

int syscall__read_enter(struct pt_regs *ctx,
                        unsigned int fd, char __user *buf, size_t count)
{
    if (!match_target_pid())
        return 0;

    // is tls session established already
    struct tls_hello_t *data = (struct tls_hello_t *)socket_table.lookup(&fd);
    if (data &&
        data->is_tls_header == 1 &&
        data->is_tls_handshake == 1)
    {
        // tls conneciton is already established via socket 'fd'
        return 0;
    }

    // cache buf and fd for processing for after-sys_read...
    struct read_args_t args = {};
    args.buf = buf;
    args.fd = fd;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    read_table.update(&pid_tgid, &args);

    return 0;
}

int syscall__read_exit(struct pt_regs *ctx)
{
    if (!match_target_pid())
        return 0;

    int count = (int)PT_REGS_RC(ctx);
    LOG("syscall__read_exit(): count=[%d]\n", count);

    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct read_args_t *args = read_table.lookup(&pid_tgid);
    if (!args)
        return 0;

    struct tls_hello_t *data = (struct tls_hello_t *)socket_table.lookup(&args->fd);
    if (!data)
    {
        read_table.delete(&pid_tgid);
        return 0;
    }

    // is it TLS ?
    if (1 == process_read(ctx, args->buf, count, data))
    {
        submit_event(ctx, data);

        // delete socket <-> address entry to avoid further processing
        socket_table.delete(&args->fd);
    }

    LOG("syscall__read_exit(): fd=[%d], buf=[%d], count=[%d]\n", args->fd, args->buf, count);

    read_table.delete(&pid_tgid);
    return 0;
}

///////////////////////////////////////////////////////////////////////////////////////////

int syscall__accept_enter(struct pt_regs *ctx,
                          int sockfd, struct sockaddr __user *addr, int __user *addrlen)
{
    if (!match_target_pid())
        return 0;

    LOG("syscall__accept_enter(): sockfd=[%d]\n", sockfd);

    u64 pid_tgid = bpf_get_current_pid_tgid();
    accept_table.update(&pid_tgid, &addr);

    return 0;
}

int syscall__accept_exit(struct pt_regs *ctx)
{
    if (!match_target_pid())
        return 0;

    int sockfd = (int)PT_REGS_RC(ctx);
    LOG("syscall__accept_exit(): sockfd=[%d]\n", sockfd);

    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sockaddr **addrp = accept_table.lookup(&pid_tgid);
    if (!addrp)
        return 0;

    struct sockaddr *addr = (struct sockaddr *)*addrp;

    struct tls_hello_t data = {};
    data.is_tls_header = 0;
    data.is_tls_handshake = 0;
    data.is_client_handshake_header = 0;
    data.is_server_handshake_header = 0;
    bpf_probe_read(&data.addr, sizeof(data.addr), addr);

    // update socket_table with the new socket entry and it's address
    struct tls_hello_t *existing_client_hello = socket_table.lookup(&sockfd);
    if (existing_client_hello)
    {
        // missing cleanup ?
        socket_table.delete(&sockfd);
    }

    // update hashtable
    socket_table.update(&sockfd, &data);

    // cleanup accept_table
    accept_table.delete(&pid_tgid);

    return 0;
}

///////////////////////////////////////////////////////////////////////////////////////////

int syscall__close_enter(struct pt_regs *ctx,
                         int sockfd)
{
    if (!match_target_pid())
        goto EXIT;

    // delete socket <-> address entry
    socket_table.delete(&sockfd);

    LOG("syscall__close_enter(): sockfd=[%d]\n", sockfd);

EXIT:
    return 0;
}

///////////////////////////////////////////////////////////////////////////////////////////

int syscall__connect_enter(struct pt_regs *ctx,
                           int sockfd, struct sockaddr __user *addr, int addrlen)
{
    if (!match_target_pid())
        return 0;

    LOG("syscall_connect_enter(): sockfd=[%d]\n", sockfd);

    u64 pid_tgid = bpf_get_current_pid_tgid();

    // cache sockfd and addr
    struct connect_args_t ce = {};
    ce.sockfd = sockfd;
    bpf_probe_read(&ce.addr, sizeof(ce.addr), addr);
    connect_table.update(&pid_tgid, &ce);

    return 0;
}

int syscall__connect_exit(struct pt_regs *ctx)
{
    if (!match_target_pid())
        return 0;

    long ret = (long)PT_REGS_RC(ctx);
    LOG("syscall_connect_exit(): ret=[%ld]\n", ret);

    // exit if error happened while connecting
    if (ret != 0)
        return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct connect_args_t *cep = connect_table.lookup(&pid_tgid);
    if (!cep)
        return 0;

    struct sockaddr *addr = &cep->addr;

    struct tls_hello_t data = {};
    data.is_tls_header = 0;
    data.is_tls_handshake = 0;
    data.is_client_handshake_header = 0;
    data.is_server_handshake_header = 0;
    __builtin_memcpy(&data.addr, &cep->addr, sizeof(data.addr));

    // update socket_table with the new socket entry and it's address
    struct tls_hello_t *existing_client_hello = socket_table.lookup(&cep->sockfd);
    if (existing_client_hello)
    {
        // missing cleanup ?
        socket_table.delete(&cep->sockfd);
    }

    // update hashtable
    socket_table.update(&cep->sockfd, &data);

    return 0;
}

)";
