.PHONY: generate build clean vmlinux

vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/headers/vmlinux.h

generate:
	go generate ./internal/bpf/

build: generate
	go build -o bin/tartarus-daemon ./cmd/tartarus-daemon
	go build -o bin/tartarus-client ./cmd/tartarus-client
	go build -o bin/tartarus-bootstrap ./cmd/tartarus-bootstrap

clean:
	rm -rf bin/ internal/bpf/jailer_bpf*.go internal/bpf/jailer_bpf*.o