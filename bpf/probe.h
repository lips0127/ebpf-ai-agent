// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Common definitions for all kernel versions

#ifndef BPF_PROBE_H
#define BPF_PROBE_H

// Event structure shared by all versions
// This structure uses dynamic sizing - see perf event output in probe_*.c
struct ebpfai_event {
    __u32 pid;
    __u32 ppid;
    char filename[1024];   // PATH_MAX is 4096, but eBPF stack limit is 512
    char argv[512];       // command line arguments (max 512 bytes)
};

#endif
