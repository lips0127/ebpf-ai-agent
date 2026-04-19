// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Probe for kernel 5.8-5.15 (ringbuf support, no full CO-RE)
// Uses vmlinux.h but not CO-RE relocations

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Ring buffer for events (kernel 5.8+)
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

    // For kernels without CO-RE, use direct offset
    // __data_loc_filename is at offset 8 in the structure
    unsigned int loc = *(unsigned int *)((char *)ctx + 8);
    bpf_probe_read_kernel_str(event->filename, sizeof(event->filename),
                              (char *)ctx + (loc & 0xFFFF));

    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
