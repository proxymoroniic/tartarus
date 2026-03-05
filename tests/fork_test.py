#!/usr/bin/env python3
import os, time

print(f"Parent PID: {os.getpid()}")
time.sleep(3)  # give time to enroll this PID

child_pid = os.fork()
if child_pid == 0:
    # Child process
    print(f"Child PID: {os.getpid()} (parent was {os.getppid()})")
    for i in range(5):
        try:
            with open("/etc/passwd") as f:
                print(f"  Child attempt {i+1}: ALLOWED (read {len(f.read())} bytes)")
        except PermissionError:
            print(f"  Child attempt {i+1}: BLOCKED")
        time.sleep(1)
else:
    # Parent process
    for i in range(5):
        try:
            with open("/etc/passwd") as f:
                print(f"  Parent attempt {i+1}: ALLOWED (read {len(f.read())} bytes)")
        except PermissionError:
            print(f"  Parent attempt {i+1}: BLOCKED")
        time.sleep(1)
    os.waitpid(child_pid, 0)
