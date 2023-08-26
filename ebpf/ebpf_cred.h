// SPDX-License-Identifier: 2023
// Copyright Alex Zhao
// eBPF Credential
//   1. credential check
// WARNING:
//   2. If RANDSTRUCT enabled, below will not working
#ifndef EBPF_CRED
#define EBPF_CRED

#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/uidgid.h>
#include <linux/cred.h>

typedef struct ebpf_cred {
	kuid_t		uid;		/* real UID of the task */
	kgid_t		gid;		/* real GID of the task */
	kuid_t		suid;		/* saved UID of the task */
	kgid_t		sgid;		/* saved GID of the task */
	kuid_t		euid;		/* effective UID of the task */
	kgid_t		egid;		/* effective GID of the task */
	kuid_t		fsuid;		/* UID for VFS ops */
	kgid_t		fsgid;		/* GID for VFS ops */    
} ebpf_cred;


static __always_inline int ebpf_get_current_task_cred(ebpf_cred *cred) {
    struct task_struct *cur_task = (struct task_struct *)bpf_get_current_task();
    if (cur_task) {
        
    } else {
        return -EACCES;
    }
}

#endif