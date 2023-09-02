// SPDX-License-Identifier: 2022
// Copyright Zhao Zhe (Alex)
//
// eBPF based syscall Clone Monitor used to build process tree
//  for application like firefox it has many threads/process
// to build a complete tree of the application monitoring clone
// for the access relations to build the monitoring tree
//
#include <linux/sched.h>

BPF_RINGBUF_OUTPUT(ring_fork_log, 16);

#define FORK_EVENT_TYPE_CLONE 1
#define FORK_EVENT_TYPE_CLONE3 2
#define FORK_EVENT_TYPE_NEW_TASK 3
#define FORK_EVENT_TYPE_RENAME_TASK 4
#define FORK_EVENT_TYPE_EXIT_TASK 5

struct event {
    // initiate comm
    char comm[16];
    // rename used new comm
    char new_comm[16];
    // initiate pid
    int parent_pid;
    // new create pid
    int child_pid;
    // types of events
    int event_type;
};

// Trace sys_enter_clone syscall   
#if 0
TRACEPOINT_PROBE(syscalls, sys_enter_clone) {
    struct task_struct *task = NULL;
    struct event *event = ring_fork_log.ringbuf_reserve(sizeof(struct event));
    int err;

    if (!event) {
        return 1;
    }

    task = (struct task_struct *)bpf_get_current_task();
    if (task != NULL) {
        bpf_probe_read_kernel_str(event->comm, sizeof(event->comm), task->comm);
    } else {
        ring_fork_log.ringbuf_discard(event, 0);
        return 1;
    }

    err = bpf_probe_read_kernel(&event->parent_pid, sizeof(int), args->parent_tidptr);
    if (err) {
        ring_fork_log.ringbuf_discard(event, 0);
        return err;
    }

    err = bpf_probe_read_kernel(&event->child_pid, sizeof(int), args->child_tidptr);
    if (err) {
        ring_fork_log.ringbuf_discard(event, 0);
        return err;
    }

    event->event_type = FORK_EVENT_TYPE_CLONE;
    ring_fork_log.ringbuf_submit(event, 0);
    return 0;
}

// Trace sys_enter_clone3 syscall
TRACEPOINT_PROBE(syscalls, sys_enter_clone3) {
    struct task_struct *task = NULL;
    struct event *event = ring_fork_log.ringbuf_reserve(sizeof(struct event));
    
    if (!event) {
        return 1;
    }

    task = (struct task_struct *)bpf_get_current_task();
    if (task != NULL) {
        bpf_probe_read_kernel_str(event->comm, sizeof(event->comm), task->comm);
    } else {
        ring_fork_log.ringbuf_discard(event, 0);
        return 1;
    }

    event->event_type = FORK_EVENT_TYPE_CLONE3;
    ring_fork_log.ringbuf_submit(event, 0);
    return 0;
}
#endif

// associate new create threads/child process with parent process
RAW_TRACEPOINT_PROBE(task_newtask) {
    // TP_PROTO(struct task_struct *task, unsigned long clone_flags),
    struct task_struct *current_task = NULL;
    struct event *event = ring_fork_log.ringbuf_reserve(sizeof(struct event));

    if (!event) {
        return 1;
    }

    current_task = (struct task_struct *)bpf_get_current_task();
    if (current_task != NULL) {
        bpf_probe_read_kernel_str(event->comm, sizeof(event->comm), current_task->comm);
        event->parent_pid = current_task->pid;
    } else {
        ring_fork_log.ringbuf_discard(event, 0);
        return 1;
    }

    struct task_struct *new_task = (struct task_struct *)ctx->args[0];
    unsigned long clone_flags = ctx->args[1];

    if (!new_task) {
        ring_fork_log.ringbuf_discard(event, 0);
        return 1;
    } else {
        event->child_pid = new_task->pid;
    }

    if (bpf_probe_read_kernel_str(event->new_comm, sizeof(event->new_comm), new_task->comm) < 0) {
        ring_fork_log.ringbuf_discard(event, 0);
        return 1;
    }

    event->event_type = FORK_EVENT_TYPE_NEW_TASK;
    ring_fork_log.ringbuf_submit(event, 0);
    return 0;
}

RAW_TRACEPOINT_PROBE(task_rename) {
    // TP_PROTO(struct task_struct *task, const char *comm),
    struct task_struct *current_task = (struct task_struct *)ctx->args[0];
    const char *comm = (const char *)ctx->args[1];
    struct event *event = ring_fork_log.ringbuf_reserve(sizeof(struct event));

    if (!event) {
        return 1;
    }

    if (!current_task || !comm) {
        ring_fork_log.ringbuf_discard(event, 0);
        return 1;
    }

    if (bpf_probe_read_kernel_str(event->comm, sizeof(event->comm), current_task->comm) < 0) {
        ring_fork_log.ringbuf_discard(event, 0);
        return 1;
    } else {
        event->parent_pid = current_task->pid;
    }

    if (bpf_probe_read_kernel_str(event->new_comm, sizeof(event->new_comm), comm) < 0) {
        ring_fork_log.ringbuf_discard(event, 0);
        return 1;
    }

    event->event_type = FORK_EVENT_TYPE_RENAME_TASK;
    ring_fork_log.ringbuf_submit(event, 0);
    return 0;
}

// Monitor process/thread exit for bookkeeping 
RAW_TRACEPOINT_PROBE(sched_process_exit) {
    struct task_struct *exit_task = (struct task_struct *)ctx->args[0];
    struct event *event = ring_fork_log.ringbuf_reserve(sizeof(struct event));

    if (!event) {
        return 1;
    }

    if (bpf_probe_read_kernel_str(event->comm, sizeof(event->comm), exit_task->comm) < 0) {
        ring_fork_log.ringbuf_discard(event, 0);
        return 1;
    } else {
        event->parent_pid = exit_task->pid;
    }

    event->event_type = FORK_EVENT_TYPE_EXIT_TASK;
    ring_fork_log.ringbuf_submit(event, 0);
    return 0;
}