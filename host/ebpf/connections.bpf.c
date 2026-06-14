#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define AF_INET 2
#define IPPROTO_TCP 6
#define TCP_ESTABLISHED 1
#define TASK_COMM_LEN 16

struct tcp_connection_event
{
    __u32 pid;
    char comm[TASK_COMM_LEN];

    __u32 saddr;
    __u32 daddr;

    __u16 sport;
    __u16 dport;
};

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u16);
} tcp_connection_config SEC(".maps");

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

    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    e->saddr = ((__u32)ctx->saddr[0]) | ((__u32)ctx->saddr[1] << 8) | ((__u32)ctx->saddr[2] << 16) |
               ((__u32)ctx->saddr[3] << 24);

    e->daddr = ((__u32)ctx->daddr[0]) | ((__u32)ctx->daddr[1] << 8) | ((__u32)ctx->daddr[2] << 16) |
               ((__u32)ctx->daddr[3] << 24);

    e->sport = ctx->sport;
    e->dport = ctx->dport;

    bpf_ringbuf_submit(e, 0);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";