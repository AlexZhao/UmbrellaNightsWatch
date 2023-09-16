// SPDX-License-Identifier: 2022
// Copyright Zhao Zhe (Alex)
//
// Configured File Access for eBPF
//
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/fdtable.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/dcache.h>

#include "ebpf/ebpf_exe.h"
#include "ebpf/ebpf_str.h"
#include "ebpf/ebpf_log.h"

BPF_RINGBUF_OUTPUT(prb_logs, 16);

// Not accurate, not go through namei, the filename is not accurate
TRACEPOINT_PROBE(syscalls, sys_enter_open) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) {
        return -EACCES;
    }
    
    struct ebpf_prb_log *log = prb_logs.ringbuf_reserve(sizeof(struct ebpf_prb_log));
    if (!log) {
        return -EACCES;
    }
    initialize_ebpf_log(log, "sys_enter_open"); 

    char app_name[32];
    ebpf_memset(app_name, 0, sizeof(app_name));
    if (ebpf_get_task_app_name(task, app_name, sizeof(app_name)) != 0) {
        prb_logs.ringbuf_discard(log, 0);
        return -EACCES;
    }
    put_ebpf_prb_log(log, app_name, ebpf_strnlen(app_name, sizeof(app_name)), TYPE_STR);
    
    pid_t pid;
    bpf_probe_read_kernel(&pid, sizeof(pid), &task->pid);
    put_ebpf_prb_log(log, (const char *)&pid, sizeof(pid), TYPE_I32);

    char filename[128];
    ebpf_memset(filename, 0, sizeof(filename));
    if (bpf_probe_read_user_str(filename, sizeof(filename), args->filename) < 0) {
        prb_logs.ringbuf_discard(log, 0);
        return -EACCES;
    }
    put_ebpf_prb_log(log, filename, ebpf_strnlen(filename, sizeof(filename)), TYPE_STR);    

    prb_logs.ringbuf_submit(log, 0);
    return 0;
}


// Not accurate, not go through namei, the filename is not accurate
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) {
        return -EACCES;
    }

    struct ebpf_prb_log *log = prb_logs.ringbuf_reserve(sizeof(struct ebpf_prb_log));
    if (!log) {
        return -EACCES;
    }
    initialize_ebpf_log(log, "sys_enter_openat"); 

    char app_name[32];
    ebpf_memset(app_name, 0, sizeof(app_name));
    if (ebpf_get_current_task_app_name(app_name, sizeof(app_name)) != 0) {
        prb_logs.ringbuf_discard(log, 0);
        return -EACCES;
    }
    put_ebpf_prb_log(log, app_name, ebpf_strnlen(app_name, sizeof(app_name)), TYPE_STR);
    pid_t pid;
    bpf_probe_read_kernel(&pid, sizeof(pid), &task->pid);
    put_ebpf_prb_log(log, (const char *)&pid, sizeof(pid), TYPE_I32);

    char filename[128];
    ebpf_memset(filename, 0, sizeof(filename));
    if (bpf_probe_read_user_str(filename, sizeof(filename), args->filename) < 0) {
        prb_logs.ringbuf_discard(log, 0);
        return -EACCES;
    }
    put_ebpf_prb_log(log, filename, ebpf_strnlen(filename, sizeof(filename)), TYPE_STR);    


    prb_logs.ringbuf_submit(log, 0);
    return 0;
}


// Not accurate, not go through namei, the filename is not accurate
TRACEPOINT_PROBE(syscalls, sys_enter_openat2) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) {
        return -EACCES;
    }

    struct ebpf_prb_log *log = prb_logs.ringbuf_reserve(sizeof(struct ebpf_prb_log));
    if (!log) {
        return -EACCES;
    }
    initialize_ebpf_log(log, "sys_enter_openat2"); 

    char app_name[32];
    ebpf_memset(app_name, 0, sizeof(app_name));
    if (ebpf_get_current_task_app_name(app_name, sizeof(app_name)) != 0) {
        prb_logs.ringbuf_discard(log, 0);
        return -EACCES;
    }
    put_ebpf_prb_log(log, app_name, ebpf_strnlen(app_name, sizeof(app_name)), TYPE_STR);
    pid_t pid;
    bpf_probe_read_kernel(&pid, sizeof(pid), &task->pid);
    put_ebpf_prb_log(log, (const char *)&pid, sizeof(pid), TYPE_I32);

    char filename[128];
    ebpf_memset(filename, 0, sizeof(filename));
    if (bpf_probe_read_user_str(filename, sizeof(filename), args->filename) < 0) {
        prb_logs.ringbuf_discard(log, 0);
        return -EACCES;
    }
    put_ebpf_prb_log(log, filename, ebpf_strnlen(filename, sizeof(filename)), TYPE_STR);    


    prb_logs.ringbuf_submit(log, 0);
    return 0;    
}
