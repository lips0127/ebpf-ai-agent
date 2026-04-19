// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Probe for kernel 6.0+ (full CO-RE + ringbuf)
// Requires: vmlinux.h with BTF

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "probe.h"

// Perf event array for outputting events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 256);
} events SEC(".maps");

SEC("tp/sched/sched_process_exec")
int handle_sched_process_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct ebpfai_event event = {0};

    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.ppid = ctx->old_pid;

    // Read filename at fixed offset (offset 8 contains __data_loc_filename)
    unsigned int loc = *(unsigned int *)((char *)ctx + 8);
    bpf_probe_read_kernel_str(event.filename, sizeof(event.filename),
                              (char *)ctx + (loc & 0xFFFF));

    // Output to perf event array
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                          &event, sizeof(event));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
