#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/fcntl.h>

BPF_HASH(jailed_procs, u32, u8);
BPF_HASH(blocked_calls, u32, u64);

static inline int is_jailed_process(u32 tgid, u32 pid) {
    u8 *is_jailed = jailed_procs.lookup(&tgid);
    if (!is_jailed) {
        is_jailed = jailed_procs.lookup(&pid);
    }
    return (is_jailed != NULL);
}

static inline int is_restricted_file(const char *filename) {
    char restricted[] = "secret.txt";
    for (int i = 0; i < 11; i++) {
        if (filename[i] != restricted[i]) {
            return 0;
        }
    }
    return 1;
}

LSM_PROBE(file_open, struct file *file, int mask) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tgid = pid_tgid & 0xFFFFFFFF;
    
    if (!is_jailed_process(tgid, pid)) {
        return 0;
    }

    struct dentry *dentry = file->f_path.dentry;
    unsigned char filename[256];
    bpf_probe_read_kernel_str(filename, sizeof(filename), dentry->d_name.name);
    
    bpf_trace_printk("Jailed process PID %d (TGID %d) opening file: %s\\n", pid, tgid, filename);

    if (is_restricted_file((const char *)filename)) {
        bpf_trace_printk("BLOCKED: Jailed process PID %d attempted to open secret.txt\\n", pid);

        u64 *count = blocked_calls.lookup(&tgid);
        u64 new_count = 1;
        if (count) {
            new_count = *count + 1;
        }
        blocked_calls.update(&tgid, &new_count);
        
        return -EPERM;
    }

    return 0;
}

int trace_openat_entry(struct pt_regs *ctx, int dfd, const char __user *filename, int flags) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tgid = pid_tgid & 0xFFFFFFFF;
    
    if (!is_jailed_process(tgid, pid)) {
        return 0;
    }

    char user_filename[256];
    bpf_probe_read_user_str(user_filename, sizeof(user_filename), filename);
    
    bpf_trace_printk("DETECTED: Jailed process PID %d (TGID %d) calling openat with: %s\\n", pid, tgid, user_filename);

    if (is_restricted_file(user_filename)) {
        bpf_trace_printk("BLOCKED: Jailed process PID %d attempted to open secret.txt\\n", pid);

        u64 *count = blocked_calls.lookup(&tgid);
        u64 new_count = 1;
        if (count) {
            new_count = *count + 1;
        }
        blocked_calls.update(&tgid, &new_count);

        #ifdef BPF_OVERRIDE_RETURN
        bpf_override_return(ctx, -EPERM);
        #endif
    }

    return 0;
}