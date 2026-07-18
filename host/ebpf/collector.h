#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define AF_INET 2
#define IPPROTO_TCP 6
#define TCP_ESTABLISHED 1
#define TASK_COMM_LEN 16
#define MAX_PATH_LEN 256

enum event_type
{
    EVENT_EXECVE,
    EVENT_CONNECT,
    EVENT_OPENAT,
    EVENT_OPENAT_EXIT,
    EVENT_RENAME,
    EVENT_RENAME_EXIT,
    EVENT_CHMOD,
    EVENT_CLONE,
    EVENT_UNLINK,
};

struct events_header
{
    __u32 type;
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u64 timestamp_ns;
    __s64 res;
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
    char filename[MAX_PATH_LEN];
    char argv[128];
};

struct opening_event
{
    struct events_header header;
    char pathname[MAX_PATH_LEN];
    __s32 dirfd;
    __u32 flags;
    __u32 mode;
    __u64 duration_ns;
};

struct pending_openat
{
    struct opening_event o_event;
    __u64 start_time_ns;
};

struct renaming_event
{
    struct events_header header;
    char oldname[MAX_PATH_LEN];
    char newname[MAX_PATH_LEN];
};

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// TODO: universal cfg
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

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);
    __type(value, struct pending_openat);
} pending_openat_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);
    __type(value, struct renaming_event);
} pending_rename_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct renaming_event);
} rename_scratch_map SEC(".maps");