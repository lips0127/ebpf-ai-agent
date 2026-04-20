//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@latest Event probe_6_0.c

package bpf

// Event represents the process execution event from the ring buffer.
// Must match struct ebpfai_event in probe.h
// This struct is for reference; the actual generated struct is in bpf_event.go
type Event struct {
	Pid     uint32
	Ppid    uint32
	Filename [1024]byte
	Argv     [512]byte
}
