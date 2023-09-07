// SPDX-License-Identifier: 2022
// Copyright Zhao Zhe (Alex)
//
// Process/Schedule monitor for what file be executed
//
#include <linux/sched.h>
#include <linux/errno.h>

#include "ebpf/ebpf_exe.h"
#include "ebpf/ebpf_log.h"

BPF_RINGBUF_OUTPUT(prb_logs, 16);

#define MAXIMUM_ARGV_LEN 32
#define MAXIMUM_LOOP 5
#define MAX_COMMNAME_LEN 32

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) {
        return -EACCES;
    }

    struct ebpf_prb_log *event = prb_logs.ringbuf_reserve(sizeof(struct ebpf_prb_log));
    const char *const *argv = NULL;
    int rlen = 0;

    if (!event || !task) {
        return -EACCES;
    }
    initialize_ebpf_log(event, "sys_enter_execve");

    char app_name[30];
    ebpf_memset(app_name, 0, sizeof(app_name));
    if (ebpf_get_task_app_name(task, app_name, sizeof(app_name)) != 0) {
        prb_logs.ringbuf_discard(event, 0);
        return -EACCES;
    }
    put_ebpf_prb_log(event, app_name, ebpf_strnlen(app_name, sizeof(app_name)), TYPE_STR);
    
    pid_t pid;
    bpf_probe_read_kernel(&pid, sizeof(pid), &task->pid);
    barrier_var(pid);
    put_ebpf_prb_log(event, (const char *)&pid, sizeof(pid), TYPE_I32);

    ebpf_memset(app_name, 0, sizeof(app_name));
    bpf_probe_read_user_str(app_name, sizeof(app_name), args->filename);
    put_ebpf_prb_log(event, app_name, ebpf_strnlen(app_name, sizeof(app_name)), TYPE_STR);
    
    argv = args->argv;

    for (int i = 0; i < MAXIMUM_LOOP; i++) {
        if (*argv) {
            ebpf_memset(app_name, 0, sizeof(app_name));
            rlen = bpf_probe_read_user_str(app_name, sizeof(app_name), *argv);
            if (rlen > 0) {
                put_ebpf_prb_log(event, app_name, ebpf_strnlen(app_name, sizeof(app_name)), TYPE_STR);
                argv ++;
            } else {
                break;
            }
        } else {
            break;
        }
    }

    prb_logs.ringbuf_submit(event, 0);
    
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_execveat) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) {
        return -EACCES;
    }

    struct ebpf_prb_log *event = prb_logs.ringbuf_reserve(sizeof(struct ebpf_prb_log));
    const char *const *argv = NULL;
    int rlen = 0;
 
    if (!event || !task) {
        return -EACCES;
    }
    initialize_ebpf_log(event, "sys_enter_execveat");

    char app_name[30];
    ebpf_memset(app_name, 0, sizeof(app_name));
    if (ebpf_get_task_app_name(task, app_name, sizeof(app_name)) != 0) {
        prb_logs.ringbuf_discard(event, 0);
        return -EACCES;
    }
    put_ebpf_prb_log(event, app_name, ebpf_strnlen(app_name, sizeof(app_name)), TYPE_STR);
    
    pid_t pid;
    bpf_probe_read_kernel(&pid, sizeof(pid), &task->pid);
    barrier_var(pid);
    put_ebpf_prb_log(event, (const char *)&pid, sizeof(pid), TYPE_I32);

    ebpf_memset(app_name, 0, sizeof(app_name));
    bpf_probe_read_user_str(app_name, sizeof(app_name), args->filename);
    put_ebpf_prb_log(event, app_name, ebpf_strnlen(app_name, sizeof(app_name)), TYPE_STR);

    argv = args->argv;

    for (int i = 0; i < MAXIMUM_LOOP; i++) {
        if (*argv) {
            ebpf_memset(app_name, 0, sizeof(app_name));
            rlen = bpf_probe_read_user_str(app_name, MAXIMUM_ARGV_LEN, *argv);
            if (rlen > 0) {
                put_ebpf_prb_log(event, app_name, ebpf_strnlen(app_name, sizeof(app_name)), TYPE_STR);
                argv ++;
            } else {
                break;
            }
        } else {
            break;
        }
    }

    prb_logs.ringbuf_submit(event, 0);
 
    return 0;
}