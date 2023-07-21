// SPDX-License-Identifier: 2022
// Copyright Alex Zhao
// eBPF based syscall
// below syscall shall not be quite often be called
// record the calling frequency associate with caller

#include <linux/sched.h>
#include <linux/errno.h>
#include <ebpf/ebpf_exe.h>

BPF_RINGBUF_OUTPUT(ring_seldom_log, 16);

#define MAXIMUM_SYSCALL_NAME_LEN 32
#define MAX_COMMNAME_LEN 128


#define SYSCALL_PTRACE 1
#define SYSCALL_MODIFY_LDT 2
#define SYSCALL_ENTER_PERSONALITY 3
#define SYSCALL_ARCH_PRCTL 4
#define SYSCALL_IOCTL 11

struct event {
    char comm[MAX_COMMNAME_LEN];
    int pid;
    int syscall;
};

static __always_inline struct event *get_seldom_syscall_event() {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) {
        return NULL;
    }

    struct event *event = ring_seldom_log.ringbuf_reserve(sizeof(struct event));
    if (!event) {
        return NULL;
    }

    if (ebpf_get_task_app_name(task, event->comm, sizeof(event->comm)) != 0) {
        ring_seldom_log.ringbuf_discard(event, 0);
        return NULL;
    }
    event->pid = task->pid;

    return event;
}

// Normall ptrace used for gdb
TRACEPOINT_PROBE(syscalls, sys_enter_ptrace) {
    struct event *event = get_seldom_syscall_event();
    if (event == NULL) {
        return -EACCES;
    }

    event->syscall = SYSCALL_PTRACE;

    ring_seldom_log.ringbuf_submit(event, 0);
    
    return 0;    
}

TRACEPOINT_PROBE(syscalls, sys_enter_modify_ldt) {
    struct event *event = get_seldom_syscall_event();
    if (event == NULL) {
        return -EACCES;
    }

    event->syscall = SYSCALL_MODIFY_LDT;

    ring_seldom_log.ringbuf_submit(event, 0);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_personality) {
    struct event *event = get_seldom_syscall_event();
    if (event == NULL) {
        return -EACCES;
    }

    event->syscall = SYSCALL_ENTER_PERSONALITY;
    
    ring_seldom_log.ringbuf_submit(event, 0);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_arch_prctl) {
    struct event *event = get_seldom_syscall_event();
    if (event == NULL) {
        return -EACCES;
    }

    event->syscall = SYSCALL_ARCH_PRCTL;

    ring_seldom_log.ringbuf_submit(event, 0);
    return 0;
}