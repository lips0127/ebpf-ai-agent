//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@latest Event probe.c

package bpf

// Event represents the process execution event from the ring buffer.
// Must match struct process_event in probe.c
type Event struct {
	Pid     uint32
	Ppid    uint32
	Filename [256]byte
}
