#ifndef COLLECTOR_CONFIG_H
#define COLLECTOR_CONFIG_H

#ifdef __VMLINUX_H__
typedef __u8 config_bool_t;
typedef __u32 config_u32_t;
#else
#include <stdint.h>
typedef uint8_t config_bool_t;
typedef uint32_t config_u32_t;
#endif

enum configured_event
{
    CONFIG_EVENT_TCP = 1U << 0,
    CONFIG_EVENT_OPEN = 1U << 1,
    CONFIG_EVENT_EXECVE = 1U << 2,
    CONFIG_EVENT_RENAME = 1U << 3,
    CONFIG_EVENT_FCHMOD = 1U << 4,
    CONFIG_EVENT_UNLINK = 1U << 5,
    CONFIG_EVENT_CLONE = 1U << 6
};

struct bpf_collector_config
{
    config_u32_t enabled_events;

    config_bool_t successful_only;
    config_bool_t open_write_only;

    config_bool_t reserved[2]; // alignment
};

#endif