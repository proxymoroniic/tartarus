#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define EPERM 1

#define FLAG_ALLOW_FILE   (1 << 0)  // bit 0
#define FLAG_ALLOW_NET    (1 << 1)  // bit 1
#define FLAG_ALLOW_EXEC   (1 << 2)  // bit 2
#define FLAG_ALLOW_SETUID (1 << 4)  // bit 4
#define FLAG_ALLOW_PTRACE (1 << 5)  // bit 5

struct process_info {
    __u64 pod_id;
    __u32 role_id;
    __u8  flags;     
    __u8  pad[3];    // alignment padding
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);    // role_id
    __type(value, __u8);   // flags bitmap
} role_flags SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct process_info);
} task_storage SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);    // PID
    __type(value, __u64);  // count
} blocked_calls SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);                 // PID
    __type(value, struct process_info);
} pending_enrollments SEC(".maps");

static __always_inline struct process_info *migrate_if_pending(__u32 pid)
{
    struct process_info *pending = bpf_map_lookup_elem(&pending_enrollments, &pid);
    if (!pending)
        return NULL;

    struct task_struct *task = bpf_get_current_task_btf();
    struct process_info *info = bpf_task_storage_get(
        &task_storage, task, NULL, BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!info)
        return NULL;

    info->pod_id  = pending->pod_id;
    info->role_id = pending->role_id;
    info->flags   = pending->flags;

    bpf_map_delete_elem(&pending_enrollments, &pid);

    return info;
}

SEC("lsm/task_alloc")
int BPF_PROG(task_alloc, struct task_struct *task, unsigned long clone_flags)
{
    struct process_info *child_info = bpf_task_storage_get(
        &task_storage, task, NULL, BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!child_info)
        return 0;

    struct task_struct *parent = bpf_get_current_task_btf();
    struct process_info *parent_info = bpf_task_storage_get(
        &task_storage, parent, NULL, 0);

    if (parent_info && parent_info->pod_id != 0) {
        child_info->pod_id  = parent_info->pod_id;
        child_info->role_id = parent_info->role_id;
        child_info->flags   = parent_info->flags;
    }

    return 0;
}

SEC("lsm/file_open")
int BPF_PROG(file_open, struct file *file)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;

    struct task_struct *task = bpf_get_current_task_btf();
    struct process_info *info = bpf_task_storage_get(
        &task_storage, task, NULL, 0);

    if (!info || info->pod_id == 0) {
        info = migrate_if_pending(tgid);
    }

    if (!info || info->pod_id == 0)
        return 0;

    __u8 *flags = bpf_map_lookup_elem(&role_flags, &info->role_id);
    if (!flags)
        return -EPERM;

    if (*flags & FLAG_ALLOW_FILE)
        return 0;

    bpf_printk("BLOCKED file_open: pid=%d role=%d", tgid, info->role_id);
    return -EPERM;
}

char _license[] SEC("license") = "GPL";