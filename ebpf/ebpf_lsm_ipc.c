// SPDX-License-Identifier: 2023
// Copyright Alex Zhao
//  IPC: sem, shm, msg all consider as IPC
#include <linux/ipc.h>
#include <linux/sem.h>
#include <linux/sched.h>
#include <linux/msg.h>

#include "ebpf/ebpf_event.h"
#include "ebpf/ebpf_exe.h"

BPF_RINGBUF_OUTPUT(lsm_events, 8);



LSM_PROBE(ipc_permission, struct kern_ipc_perm *ipcp, short flag) {
    return 0;
}



LSM_PROBE(msg_msg_alloc_security, struct msg_msg *msg) {
    return 0;
}



LSM_PROBE(msg_queue_alloc_security, struct kern_ipc_perm *msq) {
    return 0;
}



LSM_PROBE(msg_queue_associate, struct kern_ipc_perm *msq, int msqflg) {
    return 0;
}



LSM_PROBE(msg_queue_msgctl, struct kern_ipc_perm *msq, int cmd) {
    return 0;
}



LSM_PROBE(msg_queue_msgsnd, struct kern_ipc_perm *msq,
			      struct msg_msg *msg, int msqflg) {
    return 0;
}



LSM_PROBE(msg_queue_msgrcv, struct kern_ipc_perm *msq, struct msg_msg *msg,
			      struct task_struct *target, long type, int mode) {

    return 0;
}



LSM_PROBE(shm_alloc_security, struct kern_ipc_perm *shp) {
    return 0;
}




LSM_PROBE(shm_associate, struct kern_ipc_perm *shp, int shmflg) {
    return 0;
}



LSM_PROBE(shm_shmat, struct kern_ipc_perm *shp, char __user *shmaddr, int shmflg) {
    return 0;
}



LSM_PROBE(sem_alloc_security, struct kern_ipc_perm *sma) {
    return 0;
}



LSM_PROBE(sem_associate, struct kern_ipc_perm *sma, int semflg) {
    return 0;
}


/// @brief 
/// @param  
/// @param sma 
/// @param cmd 
LSM_PROBE(sem_semctl, struct kern_ipc_perm *sma, int cmd) {
    return 0;
}


/// @brief 
/// @param  
/// @param sma 
/// @param sops 
/// @param nsops 
/// @param alter 
LSM_PROBE(sem_semop, struct kern_ipc_perm *sma, struct sembuf *sops, unsigned nsops, int alter) {
    return 0;
}


LSM_PROBE(shm_shmctl, struct kern_ipc_perm *shp, int cmd) {
    return 0;
}