// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Probe for kernel 6.0+ (full CO-RE + ringbuf)
// Requires: vmlinux.h with BTF

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "probe.h"

// Ringbuf map for outputting events to userspace (kernel 6.0+)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} rb SEC(".maps");

SEC("tp/sched/sched_process_exec")
int handle_sched_process_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct ebpfai_event *event;

    // Reserve space in ringbuf
    event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
    if (!event)
        return 0;

    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->ppid = ctx->old_pid;

    // Read filename at fixed offset (offset 8 contains __data_loc_filename)
    unsigned int loc = *(unsigned int *)((char *)ctx + 8);
    bpf_probe_read_kernel_str(event->filename, sizeof(event->filename),
                              (char *)ctx + (loc & 0xFFFF));

    // argv is captured via pt_regs in later processing
    // For now, initialize to empty
    event->argv[0] = '\0';

    // Submit to ringbuf
    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
