// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Common definitions for all kernel versions

#ifndef BPF_PROBE_H
#define BPF_PROBE_H

// Event structure shared by all versions
struct process_event {
    __u32 pid;
    __u32 ppid;
    char filename[256];
};

// Map definitions
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 0);
} events SEC(".maps");

#endif
