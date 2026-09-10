# SETTING UP ENVIRONMENT
Execute command in ```ebpf/``` catalog

```
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```
```
sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_exit_fork/format
```
Hooks
```
execve
connect
openat
chmod
rename
unlink
clone/fork

SEC("tracepoint/syscalls/sys_enter_execve")
SEC("tracepoint/syscalls/sys_enter_connect")
SEC("tracepoint/syscalls/sys_enter_openat")
SEC("tracepoint/syscalls/sys_enter_chmod")
SEC("tracepoint/syscalls/sys_enter_renameat")
SEC("tracepoint/syscalls/sys_enter_unlinkat")
SEC("lsm/file_open")
```
<br></br>
