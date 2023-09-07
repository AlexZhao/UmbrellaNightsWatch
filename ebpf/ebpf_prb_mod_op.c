// SPDX-License-Identifier: 2022
// Copyright Zhao Zhe (Alex)
//
// kmod load/unload
// Monitoring the kmod load/unload
//
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/module.h>

#include "ebpf/ebpf_exe.h"
#include "ebpf/ebpf_str.h"
#include "ebpf/ebpf_log.h"

BPF_RINGBUF_OUTPUT(prb_logs, 4);

RAW_TRACEPOINT_PROBE(module_load) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) {
        return -EACCES;
    }

    struct module *mod = (struct module *)ctx->args[0];
    if (!mod) {
        return -EACCES;
    }

    struct ebpf_prb_log *log = prb_logs.ringbuf_reserve(sizeof(struct ebpf_prb_log));
    if (!log) {
        return -EACCES;
    }
    initialize_ebpf_log(log, "module_load");

    char app_name[32];
    ebpf_memset(app_name, 0, sizeof(app_name));
    if (ebpf_get_task_app_name(task, app_name, sizeof(app_name)) != 0) {
        prb_logs.ringbuf_discard(log, 0);
        return -EACCES;
    }
    put_ebpf_prb_log(log, app_name, ebpf_strnlen(app_name, sizeof(app_name)), TYPE_STR);
    
    pid_t pid;
    bpf_probe_read_kernel(&pid, sizeof(pid), &task->pid);
    barrier_var(pid);
    put_ebpf_prb_log(log, (const char *)&pid, sizeof(pid), TYPE_I32);

    ebpf_memset(app_name, 0, sizeof(app_name));
    if (bpf_probe_read_kernel_str(app_name, sizeof(app_name), mod->name) < 0) {
        put_ebpf_prb_log(log, "Unknow", 7, TYPE_STR);
    }
    put_ebpf_prb_log(log, app_name, ebpf_strnlen(app_name, sizeof(app_name)), TYPE_STR);

    prb_logs.ringbuf_submit(log, 0);
    return 0;
} 

RAW_TRACEPOINT_PROBE(module_free) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) {
        return -EACCES;
    }

    struct module *mod = (struct module *)ctx->args[0];
    if (!mod) {
        return -EACCES;
    }

    struct ebpf_prb_log *log = prb_logs.ringbuf_reserve(sizeof(struct ebpf_prb_log));
    if (!log) {
        return -EACCES;
    }
    initialize_ebpf_log(log, "module_free");

    char app_name[30];
    ebpf_memset(app_name, 0, sizeof(app_name));
    if (ebpf_get_task_app_name(task, app_name, sizeof(app_name)) != 0) {
        prb_logs.ringbuf_discard(log, 0);
        return -EACCES;
    }
    put_ebpf_prb_log(log, app_name, ebpf_strnlen(app_name, sizeof(app_name)), TYPE_STR);
    
    pid_t pid;
    bpf_probe_read_kernel(&pid, sizeof(pid), &task->pid);
    barrier_var(pid);
    put_ebpf_prb_log(log, (const char *)&pid, sizeof(pid), TYPE_I32);

    ebpf_memset(app_name, 0, sizeof(app_name));
    if (bpf_probe_read_kernel_str(app_name, sizeof(app_name), mod->name) < 0) {
        put_ebpf_prb_log(log, "Unknow", 7, TYPE_STR);
    }
    put_ebpf_prb_log(log, app_name, ebpf_strnlen(app_name, sizeof(app_name)), TYPE_STR);

    prb_logs.ringbuf_submit(log, 0);
    return 0;
} 