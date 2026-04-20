// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Probe for kernel 6.0+ (full CO-RE + ringbuf)
// Uses raw_syscalls:sys_enter to capture argv for execve syscalls

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "probe.h"

// Ringbuf map for outputting events to userspace (kernel 6.0+)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} rb SEC(".maps");

// Maximum argv bytes to capture (stack limit is 512 bytes total, keep small)
#define ARGV_BUF_SIZE 128
// Maximum argv pointers to read
#define ARGV_MAX_PTRS 8
// execve syscall number on x86_64
#define SYS_EXECVE 59

// Capture argv from raw_syscalls:sys_enter for execve
// raw_syscalls:sys_enter passes struct pt_regs * on x86_64
SEC("raw_syscalls:sys_enter")
int handle_sys_enter(struct pt_regs *ctx)
{
    struct ebpfai_event *event;
    const char *arg_ptr;
    char argv_buf[ARGV_BUF_SIZE];
    int buf_off = 0;
    int len;
    unsigned long argv_ptr;
    unsigned long filename_ptr;
    long syscall_nr;

    // Get syscall number from orig_ax
    syscall_nr = ctx->orig_ax;
    if (syscall_nr != SYS_EXECVE)
        return 0;

    // Reserve space in ringbuf
    event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
    if (!event)
        return 0;

    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->ppid = 0;

    // Get filename from di (syscall arg0)
    filename_ptr = ctx->di;
    if (filename_ptr) {
        bpf_probe_read_kernel_str(event->filename, sizeof(event->filename), (void *)filename_ptr);
    } else {
        event->filename[0] = '\0';
    }

    // Get argv from si (syscall arg1)
    argv_ptr = ctx->si;
    if (!argv_ptr) {
        event->argv[0] = '\0';
        goto submit;
    }

    // Initialize argv buffer
    argv_buf[0] = '\0';

    // Read argv[0], argv[1], ... up to ARGV_MAX_PTRS
    for (int i = 0; i < ARGV_MAX_PTRS && buf_off < ARGV_BUF_SIZE - 1; i++) {
        unsigned long arg_addr = argv_ptr + i * sizeof(unsigned long);
        unsigned long arg_ptr_value = 0;

        // Read argv[i]
        bpf_probe_read(&arg_ptr_value, sizeof(arg_ptr_value), (void *)arg_addr);
        if (arg_ptr_value == 0)
            break;

        // Read the string
        arg_ptr = (const char *)arg_ptr_value;
        len = bpf_probe_read_user_str(argv_buf + buf_off, ARGV_BUF_SIZE - buf_off - 1, arg_ptr);
        if (len > 0) {
            buf_off += len - 1;
            // Add space separator if not the last arg
            if (buf_off < ARGV_BUF_SIZE - 1) {
                argv_buf[buf_off] = ' ';
                buf_off++;
            }
        }
    }

    // Ensure null termination
    argv_buf[ARGV_BUF_SIZE - 1] = '\0';
    if (buf_off > 0 && argv_buf[buf_off - 1] == ' ') {
        argv_buf[buf_off - 1] = '\0';
    }

    // Copy to event->argv
    for (int i = 0; i < sizeof(event->argv) && i < ARGV_BUF_SIZE; i++) {
        event->argv[i] = argv_buf[i];
        if (argv_buf[i] == '\0')
            break;
    }

submit:
    // Submit to ringbuf
    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
