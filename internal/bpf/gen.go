package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -target arm64,amd64 Jailer ../../bpf/jailer.bpf.c -- -I../../bpf/headers
