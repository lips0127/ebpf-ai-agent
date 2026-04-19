// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* Perf buffer for transmitting events (compatible with older kernels) */
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 0);
} events SEC(".maps");

/* Event structure transmitted to userspace */
struct process_event {
    pid_t pid;
    pid_t ppid;
    char filename[256];
};

SEC("tp/sched/sched_process_exec")
int handle_sched_process_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct process_event event;

    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.ppid = ctx->old_pid;
    bpf_probe_read_kernel_str(event.filename, sizeof(event.filename),
                              (void *)ctx + ctx->__data_loc_filename);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
