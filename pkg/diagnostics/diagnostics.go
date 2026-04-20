// Package diagnostics provides system state checking and self-healing capabilities.
package diagnostics

import (
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
)

var (
	// lostEventCount tracks lost events across all readers
	lostEventCount atomic.Int64

	// alertLogged tracks if high-loss alert was already logged
	highLossAlerted atomic.Bool
)

// SystemState holds diagnostic information about the system.
type SystemState struct {
	KernelVersion    string
	TracerActive     string
	TracingOn        bool
	UnprivilegedBPF   int
	BTFAvailable     bool
	CPUNumber        int
	MemTotal         uint64
	LostEventCount   int64
}

// CheckSystemState reads and logs system diagnostic information.
func CheckSystemState(logger *log.Logger) {
	state := GatherSystemState()

	logger.Printf("=== System Diagnostics ===")
	logger.Printf("kernel: %s", state.KernelVersion)
	logger.Printf("cpu: %d cores", state.CPUNumber)
	logger.Printf("memory: %d MB total", state.MemTotal/1024/1024)

	// Check for active tracer
	if state.TracerActive != "nop" && state.TracerActive != "" {
		logger.Printf("WARNING: active tracer detected: %s", state.TracerActive)
		logger.Printf("WARNING: system may be running high-load ftrace tasks")
		logger.Printf("WARNING: this can cause CPU starvation for eBPF programs")
	}

	// Check tracing_on
	if !state.TracingOn {
		logger.Printf("WARNING: tracing_on=0, tracepoints are disabled")
		logger.Printf("WARNING: eBPF events will not be captured")
	}

	// Check unprivileged_bpf
	if state.UnprivilegedBPF == 2 {
		logger.Printf("ERROR: unprivileged_bpf=2 (locked), cannot load eBPF programs")
	} else if state.UnprivilegedBPF == 1 {
		logger.Printf("INFO: unprivileged_bpf=1 (privileged only)")
	} else {
		logger.Printf("INFO: unprivileged_bpf=0 (allowed)")
	}

	// Check BTF
	if state.BTFAvailable {
		logger.Printf("INFO: BTF available (full CO-RE support)")
	} else {
		logger.Printf("INFO: BTF not available (limited CO-RE)")
	}

	logger.Printf("======================")
}

// GatherSystemState collects diagnostic information from the system.
func GatherSystemState() *SystemState {
	state := &SystemState{
		KernelVersion: runtime.Version(),
	}

	// Read current_tracer
	if data, err := os.ReadFile("/sys/kernel/debug/tracing/current_tracer"); err == nil {
		state.TracerActive = strings.TrimSpace(string(data))
	}

	// Read tracing_on - try both possible locations
	tracingOnPaths := []string{
		"/sys/kernel/debug/tracing/tracing_on",
		"/proc/sys/kernel/tracing_on",
	}
	for _, path := range tracingOnPaths {
		if data, err := os.ReadFile(path); err == nil {
			state.TracingOn = strings.TrimSpace(string(data)) == "1"
			break
		}
	}

	// Read unprivileged_bpf
	if data, err := os.ReadFile("/proc/sys/kernel/unprivileged_bpf_disabled"); err == nil {
		var val int
		if _, err := fmt.Sscanf(strings.TrimSpace(string(data)), "%d", &val); err == nil {
			state.UnprivilegedBPF = val
		}
	}

	// Check BTF
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err == nil {
		state.BTFAvailable = true
	}

	// CPU count
	state.CPUNumber = runtime.NumCPU()

	// Memory info
	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "MemTotal:") {
				var memKB uint64
				fmt.Sscanf(line, "MemTotal: %d kB", &memKB)
				state.MemTotal = memKB * 1024
				break
			}
		}
	}

	state.LostEventCount = lostEventCount.Load()

	return state
}

// RecordLostEvents increments the lost event counter.
func RecordLostEvents(count int) {
	lostEventCount.Add(int64(count))

	total := lostEventCount.Load()

	// Log warning at certain thresholds
	if total >= 1000 && !highLossAlerted.Load() {
		log.Printf("CRITICAL: total lost events exceeded 1000: %d", total)
		log.Printf("CRITICAL: system is experiencing high event loss")
		log.Printf("CRITICAL: monitoring blind spots may exist")
		highLossAlerted.Store(true)
	}
}

// GetLostEventCount returns the current lost event count.
func GetLostEventCount() int64 {
	return lostEventCount.Load()
}

// CheckEventLoss detects if too many events are being lost.
func CheckEventLoss(dataLen int, expectedLen int) bool {
	if dataLen < expectedLen {
		RecordLostEvents(1)
		return true
	}
	return false
}

// ReadFileHelper is a helper to read a file and return trimmed content.
func ReadFileHelper(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// ReadTracerConfig reads the current tracer configuration.
func ReadTracerConfig() (string, error) {
	return ReadFileHelper("/sys/kernel/debug/tracing/current_tracer")
}

// ReadTracingOn reads the tracing_on state.
func ReadTracingOn() (bool, error) {
	data, err := ReadFileHelper("/proc/sys/kernel/tracing_on")
	if err != nil {
		return false, err
	}
	return data == "1", nil
}

// IsRingbufSupported checks if the kernel supports ringbuf (6.0+).
func IsRingbufSupported() bool {
	// Ringbuf was introduced in Linux 5.8, but stable support is 6.0+
	// Check if BTF is available (indicates newer kernel)
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err == nil {
		return true
	}
	return false
}

// ioReadFull is like io.ReadFull but for diagnostic purposes.
func ioReadFull(r io.Reader, buf []byte) (n int, err error) {
	for len(buf) > 0 {
		var nn int
		nn, err = r.Read(buf)
		n += nn
		buf = buf[nn:]
		if nn == 0 {
			break
		}
	}
	return
}
