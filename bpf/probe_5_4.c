// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Probe for kernel 5.4-5.7 (no BTF, no CO-RE)
// Compatible with vanilla kernel 5.4

#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <uapi/linux/ptrace.h>

// BPF helper function IDs (kernel 5.4 compatible)
static void *(*bpf_map_lookup_elem)(void *map, void *key) = (void *)1;
static long (*bpf_probe_read)(void *dst, int sz, const void *src) = (void *)4;
static long (*bpf_probe_read_str)(void *dst, int sz, const void *src) = (void *)67;
static long (*bpf_perf_event_output)(void *ctx, void *map, int flags, void *data, int size) = (void *)25;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *)14;

// Kernel 5.4 sched_process_exec tracepoint structure
// Defined manually to avoid BTF dependency
struct sched_process_exec_54 {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    __u32 common_pid;
    __u32 __data_loc_filename;
    __u32 pid;
    __u32 old_pid;
};

SEC("tracepoint/sched/sched_process_exec")
int handle_sched_process_exec(struct sched_process_exec_54 *ctx)
{
    struct process_event event;
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    event.pid = (__u32)(pid_tgid >> 32);
    event.ppid = ctx->old_pid;

    // Read filename from __data_loc (offset in lower 16 bits)
    void *filename_ptr = (__u8 *)ctx + (ctx->__data_loc_filename & 0xFFFF);
    bpf_probe_read_str(event.filename, sizeof(event.filename), filename_ptr);

    // Output via perf event (compatible with older kernels)
    bpf_perf_event_output(ctx, &events, 0, &event, sizeof(event));

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
