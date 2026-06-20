#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define AF_INET 2
#define IPPROTO_TCP 6
#define TCP_ESTABLISHED 1
#define TASK_COMM_LEN 16

enum event_type
{
    EVENT_EXECVE,
    EVENT_CONNECT,
    EVENT_OPENAT,
    EVENT_UNLINK,
    EVENT_RENAME,
    EVENT_CHMOD,
    EVENT_CLONE,
};

struct events_header
{
    __u32 type;
    __u32 pid;
    __u32 uid;
    __u64 timestamp_ns;
    char comm[TASK_COMM_LEN];
};

struct tcp_connection_event
{
    struct events_header header;
    __u32 saddr;
    __u32 daddr;

    __u16 sport;
    __u16 dport;
};

struct execution_event
{
    struct events_header header;
    char filename[256];
    char argv[128];
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

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u16);
} execution_config SEC(".maps");