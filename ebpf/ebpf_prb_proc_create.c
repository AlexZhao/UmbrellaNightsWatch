// SPDX-License-Identifier: 2022
// Copyright Zhao Zhe (Alex)
//
// Process/Schedule monitor for what file be executed
//
#include <linux/sched.h>
#include <linux/errno.h>

#include "ebpf/ebpf_exe.h"

BPF_RINGBUF_OUTPUT(ring_execve_log, 16);

#define MAXIMUM_ARGV_LEN 128
#define MAXIMUM_ARGV_ITEM 10
#define MAXIMUM_LOOP 3
#define MAX_COMMNAME_LEN 128

// TODO **argv copy to string
// BPF not able to support to move pointer within reserved events from ringbuf
struct event {
    char comm[MAX_COMMNAME_LEN];
    int pid;
    char filename[MAXIMUM_ARGV_LEN];
    char argv[MAXIMUM_ARGV_ITEM][MAXIMUM_ARGV_LEN];
    int argv_cnt;
};

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) {
        return -EACCES;
    }

    struct event *event = ring_execve_log.ringbuf_reserve(sizeof(struct event));
    const char *const *argv = NULL;
    int argv_cnt = 0;
    int rlen = 0;

    if (!event || !task) {
        return -EACCES;
    }

    if (ebpf_get_current_task_app_name(event->comm, sizeof(event->comm)) != 0) {
        ring_execve_log.ringbuf_discard(event, 0);
        return -EACCES;
    }

    event->pid = task->pid;

    bpf_probe_read_user_str(event->filename, sizeof(event->filename), args->filename);
    
    argv = args->argv;

    #pragma clang loop unroll(full)
    for (int i = 0; i < MAXIMUM_LOOP; i++) {
        if (*argv) {
            rlen = bpf_probe_read_user_str(event->argv[argv_cnt], MAXIMUM_ARGV_LEN, *argv);
            if (rlen > 0) {
                argv_cnt ++;
                argv ++;
            } else {
                break;
            }
        } else {
            break;
        }
    }

    event->argv_cnt = argv_cnt;

    ring_execve_log.ringbuf_submit(event, 0);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_execveat) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) {
        return -EACCES;
    }

    struct event *event = ring_execve_log.ringbuf_reserve(sizeof(struct event));
    const char *const *argv = NULL;
    int argv_cnt = 0;
    int rlen = 0;
 
    if (!event || !task) {
        return -EACCES;
    }


    if (ebpf_get_current_task_app_name(event->comm, sizeof(event->comm)) != 0) {
        ring_execve_log.ringbuf_discard(event, 0);
        return -EACCES;
    }
    event->pid = task->pid;

    bpf_probe_read_user_str(event->filename, sizeof(event->filename), args->filename);

    argv = args->argv;

    #pragma clang loop unroll(full)
    for (int i = 0; i < MAXIMUM_LOOP; i++) {
        if (*argv) {
            rlen = bpf_probe_read_user_str(event->argv[argv_cnt], MAXIMUM_ARGV_LEN, *argv);
            if (rlen > 0) {
                argv_cnt ++;
                argv ++;
            } else {
                break;
            }
        } else {
            break;
        }
    }

    event->argv_cnt = argv_cnt;

    ring_execve_log.ringbuf_submit(event, 0);
 
    return 0;
}