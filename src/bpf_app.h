#include <string>

const std::string BPF_PROGRAM = R"(
#include <linux/fs.h>
#include <linux/socket.h>
#include <net/inet_sock.h>
#include <net/sock.h>
#include <asm/errno.h>
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

#define READ_PAYLOAD_SIZE 12
struct read_event_t
{
    unsigned int fd;
    char payload[READ_PAYLOAD_SIZE];
    unsigned size;
};
BPF_PERF_OUTPUT(read_events);

BPF_HASH(tbl_read_buf, u64, char*);
BPF_HASH(tbl_read_fd, u64, unsigned int);
BPF_HASH(tbl_read_bytes, unsigned int, u64);

BPF_HASH(tbl_write_buf, u64, char*);
BPF_HASH(tbl_write_fd, u64, unsigned int);

long syscall__read(struct pt_regs *ctx,
                    unsigned int fd, char __user *buf, size_t count)
{
    if(!match_target_pid())
        goto EXIT;

    u64 pid_tgid = bpf_get_current_pid_tgid();

    tbl_read_buf.update(&pid_tgid, &buf);
    tbl_read_fd.update(&pid_tgid, &fd);

    bpf_trace_printk("syscall__read() invoked, fd=[%x], buf=[%x], count=[%d]\n", fd, buf, count);

EXIT:
    return 0;
}

long syscall__read_ret(struct pt_regs *ctx)
{
    if(!match_target_pid())
        goto EXIT;

    u64 pid_tgid = bpf_get_current_pid_tgid();

    int ret = (int)PT_REGS_RC(ctx);
    if (ret < 0)
        goto CLEANUP;

    char** bufp = tbl_read_buf.lookup(&pid_tgid);
    if(!bufp)
        goto CLEANUP;

    unsigned int *fdp = (unsigned int *)tbl_read_fd.lookup(&pid_tgid);
    if(!fdp)
        goto CLEANUP;

    unsigned int fd = *fdp;

    //
    size_t bytes_to_copy = (size_t) ret;
    if(bytes_to_copy > READ_PAYLOAD_SIZE)
        bytes_to_copy = READ_PAYLOAD_SIZE;

    // accumulate bytes read counter
    u64 zero = 0;
    u64 *read_bytes = tbl_read_bytes.lookup_or_try_init(&fd, &zero);
    if(read_bytes)
    {
        (*read_bytes) += bytes_to_copy;
        bpf_trace_printk("syscall__read_ret(): read bytes for socket [%x] = [%d] bytes\n", fd, *read_bytes);
    }

    char* buf = (char*)*bufp;
    bpf_trace_printk("1:bytes_to_copy=[%d]\n", bytes_to_copy);

    struct read_event_t event = {};
    event.fd = fd;
    bpf_probe_read(event.payload, bytes_to_copy, buf);
    event.size = bytes_to_copy;

    // push event to user-space
    read_events.perf_submit(ctx, &event, sizeof(event));

    bpf_trace_printk("2:bytes_to_copy=[%d], event.size=[%d]\n", bytes_to_copy, event.size);

    bpf_trace_printk("syscall__read_ret() invoked, buf=[%x], bytes=[%d]\n", buf, ret);

CLEANUP:
    tbl_read_buf.delete(&pid_tgid);
    tbl_read_fd.delete(&pid_tgid);

EXIT:
    return 0;
}

)";