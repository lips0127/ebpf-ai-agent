// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Probe for kernel 6.0+ (full CO-RE + ringbuf)
// Requires: vmlinux.h with BTF

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Ring buffer (kernel 5.8+)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("tp/sched/sched_process_exec")
int handle_sched_process_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct process_event *event;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->ppid = ctx->old_pid;

    // Full CO-RE: use BPF_CORE_READ for stable access
    bpf_probe_read_kernel_str(event->filename, sizeof(event->filename),
                              (void *)ctx + ctx->__data_loc_filename);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
