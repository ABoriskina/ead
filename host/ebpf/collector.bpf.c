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

static __always_inline int save_execve_event(__s32 fd, const char *pathname, const char *const *argv, __u32 flags, __u32 syscall_type)
{
    if (!pathname)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    __u32 zero = 0;

    struct execution_event *e = bpf_map_lookup_elem(&execve_scratch_map, &zero);

    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));

    e->header.type = EVENT_EXECVE;

    e->header.pid = pid_tgid >> 32;
    e->header.tid = pid_tgid & 0xffffffff;

    e->header.uid = bpf_get_current_uid_gid() & 0xffffffff;
    e->header.timestamp_ns = bpf_ktime_get_ns();

    e->fd = fd;
    e->flags = flags;
    e->header.syscall_type = syscall_type;

    bpf_get_current_comm(e->header.comm, sizeof(e->header.comm));

    long pathname_length = bpf_probe_read_user_str(e->pathname, sizeof(e->pathname), pathname);
    if (pathname_length < 0)
        return 0;

    if (argv)
    {
        #pragma unroll
        for (int i = 0; i < MAX_ARGS; i++)
        {
            const char *argument = 0;
            long result = bpf_probe_read_user(&argument, sizeof(argument), &argv[i]);
            if (result < 0 || !argument)
                break;

            bpf_probe_read_user_str(e->argv[i], sizeof(e->argv[i]), argument);
        }
    }

    long result = bpf_map_update_elem(&pending_execve_map, &tid, e, BPF_ANY);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    /*
    filename: 0x%08lx, argv: 0x%08lx, envp: 0x%08lx
    ((unsigned long)(REC->filename)), ((unsigned long)(REC->argv)), ((unsigned long)(REC->envp))
    */

    return save_execve_event(
        AT_FDCWD,
        (const char *)ctx->args[0],
        (const char *const *)ctx->args[1],
        0,
        EXECVE_SYSCALL
    );
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int trace_execveat(struct trace_event_raw_sys_enter *ctx)
{
    /*
    fd: 0x%08lx, filename: 0x%08lx, argv: 0x%08lx, envp: 0x%08lx, flags: 0x%08lx
    ((unsigned long)(REC->fd)), ((unsigned long)(REC->filename)), ((unsigned long)(REC->argv)), ((unsigned long)(REC->envp)), ((unsigned long)(REC->flags))
    */

    return save_execve_event(
        (__s32)ctx->args[0],
        (const char *)ctx->args[1],
        (const char *const *)ctx->args[2],
        (__u32)ctx->args[4],
        EXECVEAT_SYSCALL
    );
}

static __always_inline int save_execve_event_exit(__s64 res, __u32 syscall_type)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;

    struct execution_event *pending = bpf_map_lookup_elem(&pending_execve_map, &tid);
    if (!pending)
        return 0;

    struct execution_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
    {
        bpf_map_delete_elem(&pending_execve_map, &tid);
        return 0;
    }

    *e = *pending;

    e->header.type = EVENT_EXECVE_EXIT;
    e->header.res = res;

    bpf_map_delete_elem(&pending_execve_map, &tid);

    bpf_ringbuf_submit(e, 0);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int trace_execve_exit(struct trace_event_raw_sys_exit *ctx)
{
    /*
    0x%lx
    REC->ret
    */

    return save_execve_event_exit((__s64)ctx->ret, EXECVE_SYSCALL);
}

SEC("tracepoint/syscalls/sys_exit_execveat")
int trace_execveat_exit(struct trace_event_raw_sys_exit *ctx)
{
    /*
    0x%lx
    REC->ret
    */

    return save_execve_event_exit((__s64)ctx->ret, EXECVEAT_SYSCALL);
}

/*-----------------------------------------------------------------*/
/*---------------------------- OPENING ----------------------------*/
/*-----------------------------------------------------------------*/
static __always_inline int save_open_event(__s32 dfd, const char *pathname, __s32 flags, __s32 mode, __u32 syscall_type)
{
    struct pending_openat pending = {};

    pending.o_event.header.type = EVENT_OPENAT;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    pending.o_event.header.pid = pid_tgid >> 32;
    pending.o_event.header.tid = pid_tgid & 0xffffffff;

    pending.o_event.header.uid = bpf_get_current_uid_gid() & 0xffffffff;
    pending.o_event.header.timestamp_ns = bpf_ktime_get_ns();

    bpf_get_current_comm(pending.o_event.header.comm, sizeof(pending.o_event.header.comm));

    bpf_probe_read_user_str(pending.o_event.pathname, sizeof(pending.o_event.pathname), pathname);

    pending.o_event.dirfd = dfd;
    pending.o_event.flags = flags;
    pending.o_event.mode = mode;
    pending.start_time_ns = bpf_ktime_get_ns();
    pending.o_event.header.syscall_type = syscall_type;

    bpf_map_update_elem(&pending_openat_map, &pending.o_event.header.tid, &pending, BPF_ANY);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_open")
int trace_open(struct trace_event_raw_sys_enter *ctx)
{
    /*
    filename: 0x%08lx, flags: 0x%08lx, mode: 0x%08lx"
    ((unsigned long)(REC->filename)), ((unsigned long)(REC->flags)), ((unsigned long)(REC->mode))
    */

    return save_open_event(
        AT_FDCWD,
        (const char *)ctx->args[0],
        (__u32)ctx->args[1],
        (__u32)ctx->args[2],
        OPEN_SYSCALL
    );
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx)
{
    /*
    dfd: 0x%08lx, filename: 0x%08lx, flags: 0x%08lx, mode: 0x%08lx 
    ((unsigned long)(REC->dfd)), ((unsigned long)(REC->filename)), ((unsigned long)(REC->flags)), ((unsigned long)(REC->mode))
    */

    return save_open_event(
        (__s32)ctx->args[0],
        (const char *)ctx->args[1],
        (__u32)ctx->args[2],
        (__u32)ctx->args[3],
        OPENAT_SYSCALL
    );
}

static __always_inline int save_open_event_exit(__s64 res, __u32 syscall_type)
{
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
    e->header.res = res;

    e->duration_ns = bpf_ktime_get_ns() - pending->start_time_ns;

    bpf_map_delete_elem(&pending_openat_map, &tid);

    bpf_ringbuf_submit(e, 0);
}

SEC("tracepoint/syscalls/sys_exit_open")
int trace_open_exit(struct trace_event_raw_sys_exit *ctx)
{
    /*
    0x%lx
    REC->ret
    */

    return save_open_event_exit((__s64)ctx->ret, OPEN_SYSCALL);
}

SEC("tracepoint/syscalls/sys_exit_openat")
int trace_openat_exit(struct trace_event_raw_sys_exit *ctx)
{
    /*
    0x%lx
    REC->ret
    */

    return save_open_event_exit((__s64)ctx->ret, OPENAT_SYSCALL);
}

/*-----------------------------------------------------------------*/
/*---------------------------- RENAMING ---------------------------*/
/*-----------------------------------------------------------------*/
static __always_inline int save_rename_event(const char *oldname, const char *newname,
    __s32 olddirfd, __s32 newdirfd, __u32 flags, __u32 syscall_type)
{
    if (!oldname || !newname)
        return 0;

    __u32 zero = 0;

    struct renaming_event *e = bpf_map_lookup_elem(&rename_scratch_map, &zero);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));

    e->header.type = EVENT_RENAME;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->header.pid = pid_tgid >> 32;
    e->header.tid = pid_tgid & 0xffffffff;

    e->header.uid = bpf_get_current_uid_gid() & 0xffffffff;

    e->olddirfd = olddirfd;
    e->newdirfd = newdirfd;
    e->flags = flags;
    e->header.syscall_type = syscall_type;

    bpf_get_current_comm(e->header.comm, sizeof(e->header.comm));

    bpf_probe_read_user_str(e->oldname, sizeof(e->oldname), oldname);
    bpf_probe_read_user_str(e->newname, sizeof(e->newname), newname);

    bpf_map_update_elem(&pending_rename_map, &e->header.tid, e, BPF_ANY);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_rename")
int trace_rename(struct trace_event_raw_sys_enter *ctx)
{
    /*
    oldname: 0x%08lx, newname: 0x%08lx"
    ((unsigned long)(REC->oldname)), ((unsigned long)(REC->newname))
    */
    return save_rename_event(
        (const char *)ctx->args[0],
        (const char *)ctx->args[1],
        AT_FDCWD,
        AT_FDCWD,
        0,
        RENAME_SYSCALL);
}

SEC("tracepoint/syscalls/sys_enter_renameat")
int trace_renameat(struct trace_event_raw_sys_enter *ctx)
{
    /*
    olddfd: 0x%08lx, oldname: 0x%08lx, newdfd: 0x%08lx, newname: 0x%08lx
    ((unsigned long)(REC->olddfd)), ((unsigned long)(REC->oldname)), ((unsigned long)(REC->newdfd)), ((unsigned long)(REC->newname))
    */
    return save_rename_event(
        (const char *)ctx->args[1],
        (const char *)ctx->args[3],
        (__s32)ctx->args[0],
        (__s32)ctx->args[2],
        0,
        RENAMEAT_SYSCALL);
}

SEC("tracepoint/syscalls/sys_enter_renameat2")
int trace_renameat2(struct trace_event_raw_sys_enter *ctx)
{
    /*
    olddfd: 0x%08lx, oldname: 0x%08lx, newdfd: 0x%08lx, newname: 0x%08lx, flags: 0x%08lx
    ((unsigned long)(REC->olddfd)), ((unsigned long)(REC->oldname)), ((unsigned long)(REC->newdfd)), ((unsigned long)(REC->newname)), ((unsigned long)(REC->flags))
    */

    return save_rename_event(
        (const char *)ctx->args[1],
        (const char *)ctx->args[3],
        (__s32)ctx->args[0],
        (__s32)ctx->args[2],
        (__u32)ctx->args[4],
        RENAMEAT2_SYSCALL);
}

static __always_inline int save_rename_event_exit(__s64 res, __u32 syscall_type)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    
    struct renaming_event *pending = bpf_map_lookup_elem(&pending_rename_map, &tid);
    if (!pending)
        return 0;

    struct renaming_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) 
    {
        bpf_map_delete_elem(&pending_rename_map, &tid);
        return 0;
    }

    *e = *pending;

    e->header.type = EVENT_RENAME_EXIT;
    e->header.res = res;
    
    bpf_map_delete_elem(&pending_rename_map, &tid);

    bpf_ringbuf_submit(e, 0);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_rename")
int trace_rename_exit(struct trace_event_raw_sys_exit *ctx)
{
    /*
    0x%lx
    REC->ret
    */
    return save_rename_event_exit((__s64)ctx->ret, RENAME_SYSCALL);

}

SEC("tracepoint/syscalls/sys_exit_renameat")
int trace_renameat_exit(struct trace_event_raw_sys_exit *ctx)
{
    /*
    0x%lx
    REC->ret
    */
    return save_rename_event_exit((__s64)ctx->ret, RENAMEAT_SYSCALL);

}

SEC("tracepoint/syscalls/sys_exit_renameat2")
int trace_renameat2_exit(struct trace_event_raw_sys_exit *ctx)
{
    /*
    0x%lx
    REC->ret
    */
    return save_rename_event_exit((__s64)ctx->ret, RENAMEAT2_SYSCALL);

}

/*-----------------------------------------------------------------*/
/*------------------------------ FCHMOD ----------------------------*/
/*-----------------------------------------------------------------*/

static __always_inline int save_fchmod_event(__s32 dfd, const char *pathname,  __s32 mode,  __s32 flags, __u32 syscall_type)
{
    struct opening_event e = {};

    e.header.type = EVENT_FCHMOD;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e.header.pid = pid_tgid >> 32;
    e.header.tid = pid_tgid & 0xffffffff;

    e.header.uid = bpf_get_current_uid_gid() & 0xffffffff;
    e.header.timestamp_ns = bpf_ktime_get_ns();

    bpf_get_current_comm(e.header.comm, sizeof(e.header.comm));

    if (pathname)
        bpf_probe_read_user_str(e.pathname, sizeof(e.pathname), pathname);

    e.dirfd = dfd;
    e.flags = flags;
    e.mode = mode;
    e.header.syscall_type = syscall_type;

    bpf_map_update_elem(&pending_fchmod_map, &e.header.tid, &e, BPF_ANY);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_chmod")
int trace_chmod(struct trace_event_raw_sys_enter *ctx)
{
    /*
    filename: 0x%08lx, mode: 0x%08lx"
    ((unsigned long)(REC->filename)), ((unsigned long)(REC->mode))
    */
    
    return save_fchmod_event(
        0,
        (const char *)ctx->args[0],
        (__u32)ctx->args[1],
        0,
        FCHMOD_SYSCALL
    );
}

SEC("tracepoint/syscalls/sys_enter_fchmod")
int trace_fchmod(struct trace_event_raw_sys_enter *ctx)
{
    /*
    fd: 0x%08lx, mode: 0x%08lx
    ((unsigned long)(REC->fd)), ((unsigned long)(REC->mode))
    */
    
    return save_fchmod_event(
        (__u32)ctx->args[0],
        NULL,
        (__u32)ctx->args[1],
        0,
        FCHMOD_SYSCALL
    );
}

SEC("tracepoint/syscalls/sys_enter_fchmodat")
int trace_fchmodat(struct trace_event_raw_sys_enter *ctx)
{
    /*
    dfd: 0x%08lx, filename: 0x%08lx, mode: 0x%08lx
    ((unsigned long)(REC->dfd)), ((unsigned long)(REC->filename)), ((unsigned long)(REC->mode))
    */

    return save_fchmod_event(
        (__s32)ctx->args[0],
        (const char *)ctx->args[1],
        (__u32)ctx->args[2],
        0,
        FCHMODAT_SYSCALL
    );
}

SEC("tracepoint/syscalls/sys_enter_fchmodat2")
int trace_fchmodat2(struct trace_event_raw_sys_enter *ctx)
{
    /*
    dfd: 0x%08lx, filename: 0x%08lx, mode: 0x%08lx, flags: 0x%08lx
    ((unsigned long)(REC->dfd)), ((unsigned long)(REC->filename)), ((unsigned long)(REC->mode)), ((unsigned long)(REC->flags))
    */

    return save_fchmod_event(
        (__s32)ctx->args[0],
        (const char *)ctx->args[1],
        (__u32)ctx->args[2],
        (__u32)ctx->args[3],
        FCHMODAT2_SYSCALL
    );
}

static __always_inline int save_fchmod_event_exit(__s64 res, __u32 syscall_type)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    
    struct opening_event *pending = bpf_map_lookup_elem(&pending_fchmod_map, &tid);
    if (!pending)
        return 0;

    struct opening_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) 
    {
        bpf_map_delete_elem(&pending_fchmod_map, &tid);
        return 0;
    }

    e->header = pending->header;
    
    __builtin_memcpy(e->pathname, pending->pathname, sizeof(e->pathname));
    
    e->dirfd = pending->dirfd;
    e->flags = pending->flags;
    e->mode = pending->mode;
    
    e->header.type = EVENT_FCHMOD_EXIT;
    e->header.res = res;

    bpf_map_delete_elem(&pending_fchmod_map, &tid);

    bpf_ringbuf_submit(e, 0);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_chmod")
int trace_chmod_exit(struct trace_event_raw_sys_exit *ctx)
{
    /*
    0x%lx
    REC->ret
    */

    return save_fchmod_event_exit((__s64)ctx->ret, CHMOD_SYSCALL);
}

SEC("tracepoint/syscalls/sys_exit_fchmod")
int trace_fchmod_exit(struct trace_event_raw_sys_exit *ctx)
{
    /*
    0x%lx
    REC->ret
    */

    return save_fchmod_event_exit((__s64)ctx->ret, FCHMOD_SYSCALL);
}

SEC("tracepoint/syscalls/sys_exit_fchmodat")
int trace_fchmodat_exit(struct trace_event_raw_sys_exit *ctx)
{
    /*
    0x%lx
    REC->ret
    */

    return save_fchmod_event_exit((__s64)ctx->ret, FCHMODAT_SYSCALL);
}

SEC("tracepoint/syscalls/sys_exit_fchmodat2")
int trace_fchmodat2_exit(struct trace_event_raw_sys_exit *ctx)
{
    /*
    0x%lx
    REC->ret
    */

    return save_fchmod_event_exit((__s64)ctx->ret, FCHMODAT2_SYSCALL);
}

/*-----------------------------------------------------------------*/
/*----------------------------- UNLINK ----------------------------*/
/*-----------------------------------------------------------------*/
static __always_inline int save_unlink_event(__s32 fd, const char *pathname, __s32 flags,  __u32 syscall_type)
{
    struct unlinking_event pending = {};

    pending.header.type = EVENT_UNLINK;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    pending.header.pid = pid_tgid >> 32;
    pending.header.tid = pid_tgid & 0xffffffff;

    pending.header.uid = bpf_get_current_uid_gid() & 0xffffffff;
    pending.header.timestamp_ns = bpf_ktime_get_ns();

    bpf_get_current_comm(pending.header.comm, sizeof(pending.header.comm));

    bpf_probe_read_user_str(pending.pathname, sizeof(pending.pathname), pathname);

    pending.fd = fd;
    pending.flags = flags;
    pending.header.syscall_type = syscall_type;

    bpf_map_update_elem(&pending_unlink_map, &pending.header.tid, &pending, BPF_ANY);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlink")
int trace_unlink(struct trace_event_raw_sys_enter *ctx)
{
    /*
    pathname: 0x%08lx
    ((unsigned long)(REC->pathname))
    */

    return save_unlink_event(
        AT_FDCWD,
        (const char *)ctx->args[0],
        0,
        UNLINK_SYSCALL
    );
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int trace_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
    /*
    dfd: 0x%08lx, pathname: 0x%08lx, flag: 0x%08lx
    ((unsigned long)(REC->dfd)), ((unsigned long)(REC->pathname)), ((unsigned long)(REC->flag))
    */

    return save_unlink_event(
        (__s32)ctx->args[0],
        (const char *)ctx->args[1],
        (__u32)ctx->args[2],
        UNLINKAT_SYSCALL
    );
}

static __always_inline int save_unlink_event_exit(__s64 res, __u32 syscall_type)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    
    struct unlinking_event *pending = bpf_map_lookup_elem(&pending_unlink_map, &tid);
    if (!pending)
        return 0;

    struct unlinking_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) 
    {
        bpf_map_delete_elem(&pending_unlink_map, &tid);
        return 0;
    }

    e->header = pending->header;
    
    __builtin_memcpy(e->pathname, pending->pathname, sizeof(e->pathname));
    
    e->fd = pending->fd;
    e->flags = pending->flags;
    
    e->header.type = EVENT_UNLINK_EXIT;
    e->header.res = res;

    bpf_map_delete_elem(&pending_unlink_map, &tid);

    bpf_ringbuf_submit(e, 0);
}

SEC("tracepoint/syscalls/sys_exit_unlink")
int trace_unlink_exit(struct trace_event_raw_sys_exit *ctx)
{
    /*
    0x%lx
    REC->ret
    */

    return save_unlink_event_exit((__s64)ctx->ret, UNLINK_SYSCALL);
}

SEC("tracepoint/syscalls/sys_exit_unlinkat")
int trace_unlinkat_exit(struct trace_event_raw_sys_exit *ctx)
{
    /*
    0x%lx
    REC->ret
    */

    return save_unlink_event_exit((__s64)ctx->ret, UNLINKAT_SYSCALL);
}

char LICENSE[] SEC("license") = "GPL";