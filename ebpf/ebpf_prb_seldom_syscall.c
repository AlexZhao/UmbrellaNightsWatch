// SPDX-License-Identifier: 2022
// Copyright Zhao Zhe (Alex)
//
// eBPF based syscall
// below syscall shall not be quite often be called
// record the calling frequency associate with caller
//
#include <linux/sched.h>
#include <linux/errno.h>

#include "ebpf/ebpf_exe.h"
#include "ebpf/ebpf_log.h"

BPF_RINGBUF_OUTPUT(prb_logs, 16);

#define MAXIMUM_SYSCALL_NAME_LEN 32
#define MAX_COMMNAME_LEN 128


#define SYSCALL_PTRACE 1
#define SYSCALL_MODIFY_LDT 2
#define SYSCALL_ENTER_PERSONALITY 3
#define SYSCALL_ARCH_PRCTL 4
#define SYSCALL_IOCTL 11


static __always_inline struct ebpf_prb_log *get_seldom_syscall_event(const char *entry) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) {
        return NULL;
    }

    struct ebpf_prb_log *event = prb_logs.ringbuf_reserve(sizeof(struct ebpf_prb_log));
    if (!event) {
        return NULL;
    }
    initialize_ebpf_log(event, entry); 

    char app_name[30];
    ebpf_memset(app_name, 0, sizeof(app_name));
    if (ebpf_get_task_app_name(task, app_name, sizeof(app_name)) != 0) {
        prb_logs.ringbuf_discard(event, 0);
        return NULL;
    }

    put_ebpf_prb_log(event, app_name, ebpf_strnlen(app_name, sizeof(app_name)), TYPE_STR);
    
    pid_t pid;
    bpf_probe_read_kernel(&pid, sizeof(pid), &task->pid);
    barrier_var(pid);
    put_ebpf_prb_log(event, (const char *)&pid, sizeof(pid), TYPE_I32);

    return event;
}

// Normall ptrace used for gdb
TRACEPOINT_PROBE(syscalls, sys_enter_ptrace) {
    struct ebpf_prb_log *event = get_seldom_syscall_event("sys_enter_ptrace");
    if (event == NULL) {
        return -EACCES;
    }

    put_ebpf_prb_log(event, "ptrace", 7, TYPE_STR);
    prb_logs.ringbuf_submit(event, 0);
    
    return 0;    
}

TRACEPOINT_PROBE(syscalls, sys_enter_modify_ldt) {
    struct ebpf_prb_log *event = get_seldom_syscall_event("sys_enter_modify_ldt");
    if (event == NULL) {
        return -EACCES;
    }

    put_ebpf_prb_log(event, "modify_ldt", 11, TYPE_STR);
    prb_logs.ringbuf_submit(event, 0);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_personality) {
    struct ebpf_prb_log *event = get_seldom_syscall_event("sys_enter_personality");
    if (event == NULL) {
        return -EACCES;
    }
 
    put_ebpf_prb_log(event, "personality", 12, TYPE_STR);
    prb_logs.ringbuf_submit(event, 0);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_arch_prctl) {
    struct ebpf_prb_log *event = get_seldom_syscall_event("sys_enter_arch_prctl");
    if (event == NULL) {
        return -EACCES;
    }

    put_ebpf_prb_log(event,"arch_prctl", 11, TYPE_STR);
    prb_logs.ringbuf_submit(event, 0);

    return 0;
}