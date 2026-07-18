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
    args[3] = mode

    name: sys_enter_openat
    dfd: 0x%08lx, filename: 0x%08lx, flags: 0x%08lx, mode: 0x%08lx 
    ((unsigned long)(REC->dfd)), ((unsigned long)(REC->filename)), ((unsigned long)(REC->flags)), ((unsigned long)(REC->mode))
    */

    struct pending_openat pending = {};

    pending.o_event.header.type = EVENT_OPENAT;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    pending.o_event.header.pid = pid_tgid >> 32;
    pending.o_event.header.tid = pid_tgid & 0xffffffff;

    pending.o_event.header.uid = bpf_get_current_uid_gid() & 0xffffffff;
    pending.o_event.header.timestamp_ns = bpf_ktime_get_ns();

    bpf_get_current_comm(pending.o_event.header.comm, sizeof(pending.o_event.header.comm));

    const char *pathname = (const char *)ctx->args[1];
    bpf_probe_read_user_str(pending.o_event.pathname, sizeof(pending.o_event.pathname), pathname);

    pending.o_event.dirfd = (__s32)ctx->args[0];
    pending.o_event.flags = (__u32)ctx->args[2];
    pending.o_event.mode = (__u32)ctx->args[3];
    pending.start_time_ns = bpf_ktime_get_ns();

    bpf_map_update_elem(&pending_openat_map, &pending.o_event.header.tid, &pending, BPF_ANY);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int trace_openat_exit(struct trace_event_raw_sys_exit *ctx)
{
    /*
    name: sys_exit_openat
    0x%lx
    REC->ret
    */
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    
    struct pending_openat *pending = bpf_map_lookup_elem(&pending_openat_map, &tid);
    if (!pending)
        return 0;

    struct opening_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) 
    {
        bpf_map_delete_elem(&pending_openat_map, &tid);
        return 0;
    }

    e->header = pending->o_event.header;
    
    __builtin_memcpy(e->pathname, pending->o_event.pathname, sizeof(e->pathname));
    
    e->dirfd = pending->o_event.dirfd;
    e->flags = pending->o_event.flags;
    e->mode = pending->o_event.mode;

    e->header.type = EVENT_OPENAT_EXIT;
    e->header.res = (__u64)ctx->ret;
    e->duration_ns = bpf_ktime_get_ns() - pending->start_time_ns;

    bpf_map_delete_elem(&pending_openat_map, &tid);

    bpf_ringbuf_submit(e, 0);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";