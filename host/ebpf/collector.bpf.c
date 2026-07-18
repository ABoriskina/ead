#include "collector.h"

/*-----------------------------------------------------------------*/
/*------------------------ TCP CONNECTIONS ------------------------*/
/*-----------------------------------------------------------------*/
SEC("tracepoint/sock/inet_sock_set_state")
int trace_tcp_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
    if (ctx->family != AF_INET)
        return 0;

    if (ctx->protocol != IPPROTO_TCP)
        return 0;

    if (ctx->newstate != TCP_ESTABLISHED)
        return 0;

    __u32 key = 0;
    __u16 *target_port = bpf_map_lookup_elem(&tcp_connection_config, &key);

    if (!target_port)
        return 0;

    if (ctx->dport != *target_port)
        return 0;

    struct tcp_connection_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->header.type = EVENT_CONNECT;
    e->header.pid = bpf_get_current_pid_tgid() >> 32;
    e->header.uid = bpf_get_current_uid_gid() & 0xffffffff;

    bpf_get_current_comm(&e->header.comm, sizeof(e->header.comm));

    e->saddr = ((__u32)ctx->saddr[0]) | ((__u32)ctx->saddr[1] << 8) | ((__u32)ctx->saddr[2] << 16) |
               ((__u32)ctx->saddr[3] << 24);

    e->daddr = ((__u32)ctx->daddr[0]) | ((__u32)ctx->daddr[1] << 8) | ((__u32)ctx->daddr[2] << 16) |
               ((__u32)ctx->daddr[3] << 24);

    e->sport = ctx->sport;
    e->dport = ctx->dport;

    bpf_ringbuf_submit(e, 0);

    return 0;
}

/*-----------------------------------------------------------------*/
/*--------------------------- EXECUTION ---------------------------*/
/*-----------------------------------------------------------------*/
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execution(struct trace_event_raw_sys_enter *ctx)
{
    /*args[0] = filename
    args[1] = argv
    args[2] = envp*/

    if (!ctx->args[0])
        return 0;
    const char *filename = (const char *)ctx->args[0];

    struct execution_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->header.type = EVENT_EXECVE;
    e->header.pid = bpf_get_current_pid_tgid() >> 32;
    e->header.uid = bpf_get_current_uid_gid() & 0xffffffff;

    bpf_get_current_comm(&e->header.comm, sizeof(e->header.comm));
    bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename);

    const char *const *argv = (const char *const *)ctx->args[1];
    const char *arg0 = NULL;
    bpf_probe_read_user(&arg0, sizeof(arg0), &argv[0]);
    if (arg0)
        bpf_probe_read_user_str(e->argv, sizeof(e->argv), arg0);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/*-----------------------------------------------------------------*/
/*---------------------------- OPENING ----------------------------*/
/*-----------------------------------------------------------------*/
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx)
{
    /*args[0] = dirfd
    args[1] = pathname
    args[2] = flags
    args[3] = mode*/

    if (!ctx->args[1])
        return 0;
    const char *pathname = (const char *)ctx->args[1];

    struct opening_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->header.type = EVENT_OPENAT;
    e->header.pid = bpf_get_current_pid_tgid() >> 32;
    e->header.uid = bpf_get_current_uid_gid() & 0xffffffff;

    bpf_get_current_comm(&e->header.comm, sizeof(e->header.comm));
    bpf_probe_read_user_str(e->pathname, sizeof(e->pathname), pathname);

    e->dirfd = (__s32)ctx->args[0];
    e->flags = (__u32)ctx->args[2];
    e->mode = (__u32)ctx->args[3];

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";