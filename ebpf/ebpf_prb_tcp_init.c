// SPDX-License-Identifier: 2022
// Copyright Alex Zhao
// TCP Out Connect track back to process
#include <linux/sched.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/un.h>

#include "ebpf/ebpf_exe.h"

#define MAX_COMMNAME_LEN 128

#define MAX_UNIX_TARGET_LEN 108

#define TARGET_IPV4 1
#define TARGET_IPV6 2
#define TARGET_UNIX 3

struct ev_connect {
    char comm[MAX_COMMNAME_LEN];
    int pid;
    int op;
    int toc;
    struct sockaddr_in target;
    struct sockaddr_in6 targetv6;
    char path[MAX_UNIX_TARGET_LEN];
};

BPF_RINGBUF_OUTPUT(ring_connect_log, 16);

TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    struct task_struct *task = NULL;
    struct ev_connect *event = ring_connect_log.ringbuf_reserve(sizeof(struct ev_connect));
    if (!event) {
        return 1;
    }

    task = (struct task_struct *)bpf_get_current_task();
    if (task != NULL) {
        if (ebpf_get_current_task_app_name(event->comm, sizeof(event->comm)) !=0) {
            ring_connect_log.ringbuf_discard(event, 0);
            return 1;
        }
        event->pid = task->pid;
    } else {
        ring_connect_log.ringbuf_discard(event, 0);
        return 1;
    }


    if (!args->uservaddr) {
        ring_connect_log.ringbuf_discard(event, 0);
        return 1;
    }
    
    struct sockaddr addr;
    //struct sockaddr *addr = (struct sockaddr *)args->uservaddr;
    if (bpf_probe_read_user((void*)&addr, sizeof(struct sockaddr), args->uservaddr) < 0) {
        ring_connect_log.ringbuf_discard(event, 0);
        return 1;
    }

    if (addr.sa_family == AF_INET) {
        struct sockaddr_in *inet_addr = (struct sockaddr_in *)args->uservaddr;
        bpf_probe_read_user((void*)&event->target, sizeof(event->target), inet_addr);
        event->toc = TARGET_IPV4;
        event->op = 1;
    } else if (addr.sa_family == AF_INET6) {
        struct sockaddr_in6 *inet6_addr = (struct sockaddr_in6 *)args->uservaddr;
        bpf_probe_read_user((void*)&event->targetv6, sizeof(event->targetv6), inet6_addr);
        event->toc = TARGET_IPV6;
        event->op = 1;
    } else if (addr.sa_family == AF_UNIX) {
        struct sockaddr_un *un_addr = (struct sockaddr_un *)args->uservaddr;
        bpf_probe_read_user_str(&event->path, sizeof(event->path), un_addr->sun_path);
        event->toc = TARGET_UNIX;
        event->op = 1;
    } else {
        ring_connect_log.ringbuf_discard(event, 0);
        return 1;
    }

    ring_connect_log.ringbuf_submit(event, 0);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_sendto) {
    struct task_struct *task = NULL;
    struct ev_connect *event = ring_connect_log.ringbuf_reserve(sizeof(struct ev_connect));
    if (!event) {
        return 1;
    }

    task = (struct task_struct *)bpf_get_current_task();
    if (task != NULL) {
        if (ebpf_get_current_task_app_name(event->comm, sizeof(event->comm)) !=0) {
            ring_connect_log.ringbuf_discard(event, 0);
            return 1;
        }
        event->pid = task->pid;
    } else {
        ring_connect_log.ringbuf_discard(event, 0);
        return 1;
    }

    if (!args->addr) {
        ring_connect_log.ringbuf_discard(event, 0);
        return 1;
    }

    struct sockaddr addr;
    //struct sockaddr *addr = (struct sockaddr *)args->uservaddr;
    if (bpf_probe_read_user((void*)&addr, sizeof(struct sockaddr), args->addr) < 0) {
        ring_connect_log.ringbuf_discard(event, 0);
        return 1;
    }

    if (addr.sa_family == AF_INET) {
        struct sockaddr_in *inet_addr = (struct sockaddr_in *)args->addr;
        bpf_probe_read_user((void*)&event->target, sizeof(event->target), inet_addr);
        event->op = 2;
    } else {
        // Only IPv4 be enabled in home device
        ring_connect_log.ringbuf_discard(event, 0);
        return 1;
    }

    ring_connect_log.ringbuf_submit(event, 0);

    return 0;    
}