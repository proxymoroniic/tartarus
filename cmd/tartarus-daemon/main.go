package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"tartarus/internal/bpf"
	"tartarus/internal/policy"

	"github.com/cilium/ebpf/link"
)

func applyPolicy(objs *bpf.JailerMaps, pol policy.Policy) error {
	for _, role := range pol.Roles {
		key := role.ID
		val := role.Flags.ToBitmap()

		if err := objs.RoleFlags.Put(key, val); err != nil {
			return fmt.Errorf("setting role_flags for %s: %w", role.Name, err)
		}
		log.Printf("Loaded role %s (id=%d, flags=0x%02x)", role.Name, key, val)
	}
	return nil
}

func main() {
	pid := flag.Uint("pid", 0, "PID (TGID) to enroll in the jail")
	podID := flag.Uint64("pod", 1, "Pod ID to assign to the enrolled process")
	roleID := flag.Uint("role", 1, "Role ID to assign (e.g. 1=restricted, 2=permissive)")
	policyPath := flag.String("policy", "config/policy.json", "Path to policy JSON")
	flag.Parse()

	if *pid == 0 {
		log.Fatal("--pid is required (e.g. --pid 12345)")
	}

	var objs bpf.JailerObjects
	if err := bpf.LoadJailerObjects(&objs, nil); err != nil {
		log.Fatalf("loading BPF objects: %v", err)
	}
	defer objs.Close()

	linkFileOpen, err := link.AttachLSM(link.LSMOptions{Program: objs.FileOpen})
	if err != nil {
		log.Fatalf("attach file_open: %v", err)
	}
	defer linkFileOpen.Close()

	linkTaskAlloc, err := link.AttachLSM(link.LSMOptions{Program: objs.TaskAlloc})
	if err != nil {
		log.Fatalf("attach task_alloc: %v", err)
	}
	defer linkTaskAlloc.Close()

	pol, err := policy.LoadFromFile(*policyPath)
	if err != nil {
		log.Fatalf("loading policy from %s: %v", *policyPath, err)
	}
	if err := applyPolicy(&objs.JailerMaps, pol); err != nil {
		log.Fatalf("applying policy: %v", err)
	}

	tgid := uint32(*pid)
	info := bpf.JailerProcessInfo{
		PodId:  *podID,
		RoleId: uint32(*roleID),
	}
	if err := objs.PendingEnrollments.Put(&tgid, &info); err != nil {
		log.Fatalf("enrolling PID %d: %v", *pid, err)
	}
	log.Printf("Enrolled PID %d pod=%d role=%d (pending migration on next syscall)", *pid, *podID, *roleID)

	sig := make(chan os.Signal, 1) //kill via ctrl+c
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("Shutting down")
}
