// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Common definitions for all kernel versions

#ifndef BPF_PROBE_H
#define BPF_PROBE_H

// Event structure shared by all versions
struct ebpfai_event {
    __u32 pid;
    __u32 ppid;
    char filename[256];
};

#endif
