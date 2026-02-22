import time
import os

print(f"Victim Process Started. PID: {os.getpid()}")

attempt = 0
while True:
    attempt += 1
    try:
        with open("secret.txt", "r") as f:
            print(f"SUCCESS (Attempt {attempt}): Read data: {f.read().strip()}")
    except PermissionError:
        print("BLOCKED: Access denied by BpfJailer!")
    except Exception as e:
        print(f"Error: {e}")
    time.sleep(2)