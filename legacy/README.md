# Tartarus

A BPF-based process jailer that restricts file access for targeted processes using Linux kernel security mechanisms.

Inspired by [BpfJailer: eBPF Mandatory Access Control](https://lpc.events/event/19/contributions/2159/attachments/1833/3929/BpfJailer%20LPC%202025.pdf) (LPC 2025). This is a minimal, learning-oriented take on the same ideas—not a production system and nowhere near the scope of Meta’s BpfJailer.


I'm rewriting this in **Go** and **eBPF** (cilium/ebpf) to learn both. I use AI to help sketch out the plan and steps, but I write the code myself so it actually sticks—reverse vibe-coding, if you will. I'll document the changes and my learnings as I go. 

## Overview

Tartarus uses eBPF (extended Berkeley Packet Filter) to intercept file system calls and block jailed processes from accessing restricted files. It leverages two approaches:

1. **LSM BPF Hooks** (preferred) - Directly blocks file access at the Linux Security Module layer by returning `-EPERM`
2. **Kprobes** (fallback) - Monitors `openat` syscalls and can block access if `CONFIG_BPF_KPROBE_OVERRIDE` is enabled

Currently, Tartarus blocks access to `secret.txt` for any jailed process.

## Requirements

- Linux kernel with BPF support (5.7+ recommended for LSM BPF)
- Root privileges
- BCC (BPF Compiler Collection)
- Python 3

## Installation

```bash
pip install -r requirements.txt
```

On Ubuntu/Debian:
```bash
apt-get install -y bpfcc-tools python3-bpfcc linux-headers-$(uname -r)
```

## Usage

### 1. Start the victim process (for testing)

```bash
cd tests
python3 victim.py
```

Note the PID printed by the victim process.

### 2. Jail the process

In another terminal, run as root:

```bash
sudo python3 main.py <PID>
```

Replace `<PID>` with the PID from step 1.

### 3. Observe the blocking

The victim process will now receive "Permission denied" errors when attempting to read `secret.txt`. The jailer will display trace messages showing blocked access attempts.

## macOS Users (Lima VM)

Since BPF requires a Linux kernel, macOS users can use Lima to run Tartarus in a VM:

```bash
# Create and start the VM
limactl create --name=tartarus lima.yaml
limactl start tartarus

# Shell into the VM
limactl shell tartarus

# Navigate to the mounted directory
cd /Users/amaldb/sandbox/Tartarus
```

## Project Structure

```
Tartarus/
├── main.py          # Python loader and CLI interface
├── jailer.c         # BPF program (LSM hooks + kprobes)
├── requirements.txt # Python dependencies
├── lima.yaml        # Lima VM configuration for macOS
└── tests/
    ├── victim.py    # Test process that reads secret.txt
    └── secret.txt   # Protected file
```

## How It Works

1. The BPF program maintains a hash map (`jailed_procs`) of PIDs that are "jailed"
2. When a jailed process attempts to open a file, the LSM `file_open` hook intercepts the call
3. If the filename matches `secret.txt`, the hook returns `-EPERM`, blocking access
4. Statistics on blocked calls are tracked in the `blocked_calls` map

## Development Journey & Learnings

Building Tartarus was a deep dive into Linux kernel security mechanisms. Here's what the journey looked like:

### The Initial Goal

The idea was simple: create a lightweight "jail" that could selectively block a process from accessing specific files, without containers or complex sandboxing frameworks. eBPF seemed like the perfect tool—it runs in the kernel, has low overhead, and can intercept system calls.

### Challenge 1: Monitoring vs. Actually Blocking

The first attempt likely used **kprobes** to trace `openat` syscalls. This worked great for *detecting* file access—you could see every file a process tried to open. But detection isn't blocking.

**Learning:** Kprobes are primarily an observability tool. To actually *block* a syscall, you need either:
- `bpf_override_return()` (requires `CONFIG_BPF_KPROBE_OVERRIDE`, which many kernels disable for safety)
- LSM BPF hooks, which are designed for security decisions

### Challenge 2: LSM BPF to the Rescue (Sort Of)

LSM (Linux Security Modules) hooks are the "official" way to make security decisions in the kernel. The `file_open` hook can return `-EPERM` to deny access. Perfect!

**Learning:** LSM BPF is powerful but requires:
- Kernel 5.7+ with `CONFIG_BPF_LSM=y`
- The `bpf` LSM to be enabled in the boot parameters (`lsm=bpf,...`)

Many systems don't have this enabled by default, hence the fallback to kprobes.

### Challenge 3: Cross-Architecture Syscall Names

When attaching kprobes to syscalls, the function names differ by architecture:
- x86_64: `__x64_sys_openat`
- ARM64: `__arm64_sys_openat`
- Generic: `do_sys_openat2`

**Learning:** Never hardcode syscall entry points. Try multiple names and handle failures gracefully.

### Challenge 4: macOS Development

BPF is a Linux kernel feature—it doesn't exist on macOS. The solution was Lima, a lightweight VM tool that:
- Runs an Ubuntu VM with full BPF support
- Mounts the project directory for seamless editing
- Provides a near-native development experience

**Learning:** Lima (or similar tools like UTM/QEMU) is essential for kernel-level development on macOS.

### Challenge 5: PID vs TGID

Linux has both PIDs and TGIDs (Thread Group IDs). A multi-threaded process has one TGID but multiple PIDs. The jail needed to check both to catch all threads of a jailed process.

**Learning:** Always consider `bpf_get_current_pid_tgid()` returns both values packed into a u64. Extract and check both.


## Limitations

- Currently only blocks access to `secret.txt` (hardcoded)
- LSM BPF requires kernel 5.7+ with `CONFIG_BPF_LSM` enabled
- Kprobe-based blocking requires `CONFIG_BPF_KPROBE_OVERRIDE`

## License

MIT
