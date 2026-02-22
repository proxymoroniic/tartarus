from bcc import BPF
import os
import sys
import time

# 1. Load the BPF program
try:
    b = BPF(src_file="jailer.c")
    print("[*] BPF program loaded successfully")
except Exception as e:
    print(f"[!] Error loading BPF program: {e}")
    sys.exit(1)

# 2. Access the maps
jailed_procs = b["jailed_procs"]
blocked_calls = b["blocked_calls"]

# 3. LSM hooks are automatically attached by BCC when using LSM_PROBE
# If LSM BPF is available, the file_open hook will be active and can BLOCK access
# If not available, we'll use kprobes as fallback
print("[*] LSM hook (file_open) is auto-attached if LSM BPF is available")
print("[*] LSM hooks can DIRECTLY BLOCK file access by returning -EPERM")

# 4. Also attach kprobes as fallback/detection method
# Kprobes can detect and potentially block (if CONFIG_BPF_KPROBE_OVERRIDE is enabled)
print("[*] Attaching kprobes for additional detection/monitoring...")
try:
    print("[*] Attaching kprobes to sys_openat...")
    try:
        # Try different syscall entry point names depending on architecture
        import platform
        arch = platform.machine()
        
        # Try the generic name first
        try:
            b.attach_kprobe(event="do_sys_openat", fn_name="trace_openat_entry")
            print("[*] Attached kprobe to do_sys_openat")
        except Exception as e1:
            print(f"[!] Could not attach to do_sys_openat: {e1}")
            # Try architecture-specific names
            if arch == "aarch64" or arch == "arm64":
                try:
                    b.attach_kprobe(event="__arm64_sys_openat", fn_name="trace_openat_entry")
                    print("[*] Attached kprobe to __arm64_sys_openat")
                except Exception as e2:
                    print(f"[!] Could not attach to __arm64_sys_openat: {e2}")
                    raise
            else:
                try:
                    b.attach_kprobe(event="__x64_sys_openat", fn_name="trace_openat_entry")
                    print("[*] Attached kprobe to __x64_sys_openat")
                except Exception as e2:
                    print(f"[!] Could not attach to __x64_sys_openat: {e2}")
                    raise
        print("[!] NOTE: Kprobes can DETECT but may not BLOCK without CONFIG_BPF_KPROBE_OVERRIDE")
    except Exception as e:
        print(f"[!] Failed to attach kprobes: {e}")
        print("[!] Make sure:")
        print("    - Kernel has CONFIG_BPF_KPROBE_OVERRIDE enabled (for blocking with kprobes)")
        print("    - Running as root/sudo")
        print("    - Kernel symbols are available")
        sys.exit(1)

def enroll_pid(target_pid):
    """Enrolls a process into the jail."""
    pid_c = b.get_table("jailed_procs").Key(target_pid)
    val_c = b.get_table("jailed_procs").Leaf(1)
    jailed_procs[pid_c] = val_c
    print(f"[*] PID {target_pid} has been jailed.")
    print(f"[*] This process will now be BLOCKED from accessing 'secret.txt'")
    # Verify
    check_val = jailed_procs.get(pid_c)
    if check_val:
        print(f"[*] Confirmed: PID {target_pid} is in jail map")
    else:
        print(f"[!] Warning: Could not verify PID {target_pid} in map")
    
    # Initialize blocked calls counter
    blocked_key = b.get_table("blocked_calls").Key(target_pid)
    zero = b.get_table("blocked_calls").Leaf(0)
    blocked_calls[blocked_key] = zero

def monitor():
    """Reads the kernel trace pipe to show blocks happening."""
    print("[*] Monitoring for security events... (Ctrl-C to stop)")
    print("[*] You should see file access attempts from jailed processes")
    print("[*] Access to 'secret.txt' will be BLOCKED for jailed processes")
    print("")
    while True:
        try:
            (task, pid, cpu, flags, ts, msg) = b.trace_fields()
            print(f"[TRACE] {msg.decode('utf-8')}")
        except KeyboardInterrupt:
            print("\n[*] Shutting down...")
            # Show statistics
            print("\n[*] Blocked calls statistics:")
            for k, v in blocked_calls.items():
                if v.value > 0:
                    print(f"    PID {k.value}: {v.value} blocked attempts")
            sys.exit()
        except ValueError:
            continue

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: sudo python3 main.py <PID_TO_JAIL>")
        sys.exit(1)

    target_pid = int(sys.argv[1])
    
    enroll_pid(target_pid)
    monitor()
