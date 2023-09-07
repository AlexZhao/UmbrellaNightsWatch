// SPDX-License-Identifier: 2022
// Copyright Zhao Zhe (Alex)
//
// TCP/UDP egress connection track back to application
//
#include <linux/sched.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/un.h>
#include <linux/errno.h>

#include "ebpf/ebpf_exe.h"
#include "ebpf/ebpf_log.h"

BPF_RINGBUF_OUTPUT(prb_logs, 16);

TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    if (!args->uservaddr) {
        return -EACCES;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) {
        return -EACCES;
    }

    struct ebpf_prb_log *event = prb_logs.ringbuf_reserve(sizeof(struct ebpf_prb_log));
    if (!event) {
        return -EACCES;
    }
    initialize_ebpf_log(event, "sys_enter_connect"); 
    
    char app_name[32];
    ebpf_memset(app_name, 0, sizeof(app_name));
    if (ebpf_get_task_app_name(task, app_name, sizeof(app_name)) !=0) {
        prb_logs.ringbuf_discard(event, 0);
        return -EACCES;
    }
    put_ebpf_prb_log(event, app_name, ebpf_strnlen(app_name, sizeof(app_name)), TYPE_STR);

    pid_t pid;
    bpf_probe_read_kernel(&pid, sizeof(pid), &task->pid);
    put_ebpf_prb_log(event, (const char *)&pid, sizeof(pid), TYPE_I32);
    
    struct sockaddr addr;
    if (bpf_probe_read_user((void*)&addr, sizeof(struct sockaddr), args->uservaddr) < 0) {
        prb_logs.ringbuf_submit(event, 0);
        return -EACCES;
    }

    if (addr.sa_family == AF_INET) {
        struct sockaddr_in inet_addr;
        if (bpf_probe_read_user((void*)&inet_addr, sizeof(inet_addr), (struct sockaddr_in *)args->uservaddr) < 0) {
            prb_logs.ringbuf_submit(event, 0);
            return -EACCES;
        }
        put_ebpf_prb_log(event, "TCP", 4, TYPE_STR);
        put_ebpf_prb_log(event, (const char *)&inet_addr, sizeof(inet_addr), TYPE_SOCKADDR_4);
    } else if (addr.sa_family == AF_INET6) {
        struct sockaddr_in6 inet6_addr;
        if (bpf_probe_read_user((void*)&inet6_addr, sizeof(inet6_addr), (struct sockaddr_in6 *)args->uservaddr) < 0) {
            prb_logs.ringbuf_submit(event, 0);
            return -EACCES;
        }
        put_ebpf_prb_log(event, "TCP", 4, TYPE_STR);
        put_ebpf_prb_log(event, (const char *)&inet6_addr, sizeof(inet6_addr), TYPE_SOCKADDR_6);
    } else if (addr.sa_family == AF_UNIX) {
        struct sockaddr_un un_addr;
        if (bpf_probe_read_user_str((void*)&un_addr, sizeof(un_addr), (struct sockaddr_un *)args->uservaddr) < 0) {
            prb_logs.ringbuf_submit(event, 0);
            return -EACCES;
        }
        put_ebpf_prb_log(event, "UNIX", 5, TYPE_STR);
        put_ebpf_prb_log(event, (const char *)&un_addr, sizeof(un_addr), TYPE_SOCKADDR_UN);
    } else {
        put_ebpf_prb_log(event, "UnknowProtocol", 15, TYPE_STR);
    }

    prb_logs.ringbuf_submit(event, 0);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_sendto) {
    if (!args->addr) {
        return -EACCES;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) {
        return -EACCES;
    }

    struct ebpf_prb_log *event = prb_logs.ringbuf_reserve(sizeof(struct ebpf_prb_log));
    if (!event) {
        return -EACCES;
    }
    initialize_ebpf_log(event, "sys_enter_sendto"); 

    char app_name[32];
    ebpf_memset(app_name, 0, sizeof(app_name));
    if (ebpf_get_task_app_name(task, app_name, sizeof(app_name)) !=0) {
        prb_logs.ringbuf_discard(event, 0);
        return -EACCES;
    }
    put_ebpf_prb_log(event, app_name, ebpf_strnlen(app_name, sizeof(app_name)), TYPE_STR);

    pid_t pid;
    bpf_probe_read_kernel(&pid, sizeof(pid), &task->pid);
    put_ebpf_prb_log(event, (const char *)&pid, sizeof(pid), TYPE_I32);

    struct sockaddr addr;
    if (bpf_probe_read_user((void*)&addr, sizeof(struct sockaddr), args->addr) < 0) {
        prb_logs.ringbuf_discard(event, 0);
        return -EACCES;
    }

    if (addr.sa_family == AF_INET) {
        struct sockaddr_in inet_addr;
        if (bpf_probe_read_user((void*)&inet_addr, sizeof(inet_addr), (struct sockaddr_in *)args->addr) < 0) {
            prb_logs.ringbuf_submit(event, 0);
            return -EACCES;
        }
        put_ebpf_prb_log(event, "UDP", 4, TYPE_STR);
        put_ebpf_prb_log(event, (const char *)&inet_addr, sizeof(inet_addr), TYPE_SOCKADDR_4);
    } else if (addr.sa_family == AF_INET6) {
        struct sockaddr_in6 inet6_addr;
        if (bpf_probe_read_user((void*)&inet6_addr, sizeof(inet6_addr), (struct sockaddr_in6 *)args->addr) < 0) {
            prb_logs.ringbuf_submit(event, 0);
            return -EACCES;
        }
        put_ebpf_prb_log(event, "UDP", 4, TYPE_STR);
        put_ebpf_prb_log(event, (const char *)&inet6_addr, sizeof(inet6_addr), TYPE_SOCKADDR_6);
    } else {
        put_ebpf_prb_log(event, "UnknowProtocol", 15, TYPE_STR);
    }

    prb_logs.ringbuf_submit(event, 0);

    return 0;    
}