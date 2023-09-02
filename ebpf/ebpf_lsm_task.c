// SPDX-License-Identifier: 2023
// Copyright Zhao Zhe (Alex)
//
// eBPF based Security Module to control Linux task
// 
//
#include <asm/signal.h>

#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/resource.h>
#include <linux/prctl.h>

#include <linux/sched/prio.h>

#include "ebpf/ebpf_event.h"
#include "ebpf/ebpf_str.h"
#include "ebpf/ebpf_exe.h"

BPF_RINGBUF_OUTPUT(lsm_events, 8);

// simple comm to identify task, it shall use task_struct with 
// executable file and credential
struct task_info {
    char comm[16];
};

// TODO extend the int to be configured as set of signal
// a struct with array of sigs
BPF_HASH(task_kill_protect, struct task_info, int);
BPF_HASH(task_ptrace_protect, struct task_info, int);

// Prevent configured process from sigkill
LSM_PROBE(task_kill, struct task_struct *p, struct kernel_siginfo *info, int sig, const struct cred *cred) {

    struct task_info task_comm;
    ebpf_memset(task_comm.comm, 0, sizeof(task_comm.comm));
    if (ebpf_get_task_app_name(p, task_comm.comm, sizeof(task_comm.comm)) != 0) {
        return -EACCES;
    }

    if (task_kill_protect.lookup(&task_comm) != NULL) {
        // Only config default SIGKILL/SIGSTOP
        if (sig != SIGKILL && sig != SIGSTOP) {
            return 0;
        }

        struct ebpf_event *event = lsm_events.ringbuf_reserve(sizeof(struct ebpf_event));
        if (event == NULL) {
            return -EPERM;
        }

        initialize_ebpf_event_log(event, "task_kill");
        put_ebpf_event_log(event, "protect_kill", 13, TYPE_STR);
        put_ebpf_event_log(event, task_comm.comm, ebpf_strnlen(task_comm.comm, sizeof(task_comm.comm)), TYPE_STR);
        lsm_events.ringbuf_submit(event, 0);

        return -EPERM;
    }
    
    return 0;
}


/// @brief Used to avoid starve process
/// @param  
/// @param p 
/// @param nice 
LSM_PROBE(task_setnice, struct task_struct *p, int nice) {
    struct task_info init_task_comm;
    ebpf_memset(init_task_comm.comm, 0, sizeof(init_task_comm));
    if (ebpf_get_current_task_app_name(init_task_comm.comm, sizeof(init_task_comm)) != 0) {
        return -EACCES;
    } 

    struct task_info tar_task_comm;
    ebpf_memset(tar_task_comm.comm, 0, sizeof(tar_task_comm));
    if (ebpf_get_task_app_name(p, tar_task_comm.comm, sizeof(tar_task_comm)) != 0) {
        return -EACCES;
    }

    struct ebpf_event *event = lsm_events.ringbuf_reserve(sizeof(struct ebpf_event));
    if (event == NULL) {
        return -EPERM;
    }

    initialize_ebpf_event_log(event, "task_setnice");
    put_ebpf_event_log(event, init_task_comm.comm, ebpf_strnlen(init_task_comm.comm, sizeof(init_task_comm.comm)), TYPE_STR);
    put_ebpf_event_log(event, tar_task_comm.comm, ebpf_strnlen(tar_task_comm.comm, sizeof(tar_task_comm.comm)), TYPE_STR);

    if (ebpf_strncmp(init_task_comm.comm, tar_task_comm.comm, sizeof(init_task_comm)) != 0) {
        int prio = NICE_TO_PRIO(nice);
        put_ebpf_event_log(event, (const char*)&prio, sizeof(prio), TYPE_I32);
        lsm_events.ringbuf_submit(event, 0);
        return -EPERM;
    }

    lsm_events.ringbuf_discard(event, 0);
    return 0;
}


/// @brief  IO proirity set for task
/// @param  
/// @param p 
/// @param ioprio 
LSM_PROBE(task_setioprio, struct task_struct *p, int ioprio) {
    return -EPERM;
}


/// @brief task related resource limit set
/// @param  
/// @param p 
/// @param resource 
/// @param new_rlim 
LSM_PROBE(task_setrlimit, struct task_struct *p, unsigned int resource, struct rlimit *new_rlim) {
    return 0;
}


/// @brief 
/// @param  
/// @param  
/// @param old 
/// @param flags 
LSM_PROBE(task_fix_setuid, struct cred *new, const struct cred *old, int flags) {
    return 0;
}


/// @brief 
/// @param  
/// @param  
/// @param old 
/// @param flags 
LSM_PROBE(task_fix_setgid, struct cred *new, const struct cred *old, int flags) {
    return 0;
}


/// @brief 
/// @param  
/// @param  
/// @param old 
LSM_PROBE(task_fix_setgroups, struct cred *new, const struct cred *old) {
    return 0;
}

/// @brief 
/// @param  
/// @param p 
/// @param pgid 
LSM_PROBE(task_setpgid, struct task_struct *p, pid_t pgid) {
    return 0;
}




/// @brief Check the task allow to be modified its scheduler or not, by default not
///        allow to change from SCHED_NORMAL to SCHED_RT, also not allow SCHED_IDLE
/// @param  
/// @param p 
LSM_PROBE(task_setscheduler, struct task_struct *p) {
    struct task_info tar_task_comm;
    ebpf_memset(tar_task_comm.comm, 0, sizeof(tar_task_comm.comm));
    if (ebpf_get_task_app_name(p, tar_task_comm.comm, sizeof(tar_task_comm.comm)) != 0) {
        return-EACCES;
    }

    struct ebpf_event *event = lsm_events.ringbuf_reserve(sizeof(struct ebpf_event));
    if (event == NULL) {
        return -EPERM;
    }

    initialize_ebpf_event_log(event, "task_setscheduler");
    put_ebpf_event_log(event, tar_task_comm.comm, ebpf_strnlen(tar_task_comm.comm, sizeof(tar_task_comm.comm)), TYPE_STR);

    struct task_info init_task_comm;
    ebpf_memset(init_task_comm.comm, 0, sizeof(init_task_comm.comm));
    if (ebpf_get_current_task_app_name(init_task_comm.comm, sizeof(init_task_comm.comm)) != 0) {
        lsm_events.ringbuf_discard(event, 0);
        return -EACCES;
    }
    put_ebpf_event_log(event, init_task_comm.comm, ebpf_strnlen(init_task_comm.comm, sizeof(init_task_comm.comm)), TYPE_STR);

    if (ebpf_strncmp(init_task_comm.comm, tar_task_comm.comm, sizeof(tar_task_comm)) != 0) {
        lsm_events.ringbuf_submit(event, 0);
        return -EPERM;
    }

    lsm_events.ringbuf_discard(event, 0);
    return 0;
}



/// @brief Operation on Processes/Threads, manipulates behavior of calling process/thread
///        many not daily use configuration on process/thread
///        book update, main parts of not teaching in class
///        this called at the entry of syscall, ptr are mostly userspace memory
/// @param  
/// @param option 
/// @param arg2 
/// @param arg3 
/// @param arg4 
/// @param arg5 
LSM_PROBE(task_prctl, int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5) {
    struct task_info task_comm;
    ebpf_memset(task_comm.comm, 0, sizeof(task_comm.comm));
    if (ebpf_get_current_task_app_name(task_comm.comm, sizeof(task_comm.comm)) != 0) {
        return -EACCES;
    }

    struct ebpf_event *event = lsm_events.ringbuf_reserve(sizeof(struct ebpf_event));
    if (event == NULL) {
        return -EPERM;
    }

    initialize_ebpf_event_log(event, "task_prctl");
    put_ebpf_event_log(event, task_comm.comm, ebpf_strnlen(task_comm.comm, sizeof(task_comm.comm)), TYPE_STR);

    switch (option) {
        case PR_CAP_AMBIENT:
            put_ebpf_event_log(event, "cap_ambient", 12, TYPE_STR);
            switch (arg2) {
                case PR_CAP_AMBIENT_RAISE:
                    put_ebpf_event_log(event, "cap_ambient_raise", 18, TYPE_STR);
                    break;
                case PR_CAP_AMBIENT_LOWER:
                    put_ebpf_event_log(event, "cap_ambient_lower", 18, TYPE_STR);
                    break;
                case PR_CAP_AMBIENT_IS_SET:
                    put_ebpf_event_log(event, "cap_ambient_is_set", 19, TYPE_STR);
                    lsm_events.ringbuf_discard(event, 0);
                    return 0;
                case PR_CAP_AMBIENT_CLEAR_ALL:
                    put_ebpf_event_log(event, "cap_ambient_clear_all", 22, TYPE_STR);
                    break;
                default:
                    put_ebpf_event_log(event, "unknown", 8, TYPE_STR);
                    lsm_events.ringbuf_submit(event, 0);
                    return -EPERM;
            }
            break;
        case PR_CAPBSET_READ:
            put_ebpf_event_log(event, "capbset_read", 13, TYPE_STR);
            break;
        case PR_CAPBSET_DROP:
            put_ebpf_event_log(event, "capbset_drop", 13, TYPE_STR);
            break;
        case PR_SET_CHILD_SUBREAPER:
            put_ebpf_event_log(event, "set_child_subreaper", 20, TYPE_STR);
            break;
        case PR_GET_CHILD_SUBREAPER:
            put_ebpf_event_log(event, "get_child_subreaper", 20, TYPE_STR);
            break;
        case PR_SET_DUMPABLE:
            put_ebpf_event_log(event, "set_dumpable", 13, TYPE_STR);
            break;
        case PR_GET_DUMPABLE:
            put_ebpf_event_log(event, "get_dumpable", 13, TYPE_STR);
            break;
        // PowerPC
        case PR_SET_ENDIAN:
            put_ebpf_event_log(event, "set_endian", 11, TYPE_STR);
            break;
        case PR_GET_ENDIAN:
            put_ebpf_event_log(event, "get_endian", 11, TYPE_STR);
            break;
        // MIPS
        case PR_SET_FP_MODE:
            put_ebpf_event_log(event, "set_fp_mode", 12, TYPE_STR);
            break;
        case PR_GET_FP_MODE:
            put_ebpf_event_log(event, "get_fp_mode", 12, TYPE_STR);
            break;
        // IA64
        case PR_SET_FPEMU:
            put_ebpf_event_log(event, "set_fpemu", 10, TYPE_STR);
            break;
        case PR_GET_FPEMU:
            put_ebpf_event_log(event, "get_fpemu", 10, TYPE_STR);
            break;
        // PowerPC
        case PR_SET_FPEXC:
            put_ebpf_event_log(event, "set_fpexc", 10, TYPE_STR);
            break;
        case PR_GET_FPEXC:
            put_ebpf_event_log(event, "get_fpexc", 10, TYPE_STR);
            break;
        case PR_SET_IO_FLUSHER:
            put_ebpf_event_log(event, "set_io_flusher", 15, TYPE_STR);
            break;
        case PR_GET_IO_FLUSHER:
            put_ebpf_event_log(event, "get_io_flusher", 15, TYPE_STR);
            break;
        case PR_SET_KEEPCAPS:
            put_ebpf_event_log(event, "set_keepcaps", 13, TYPE_STR);
            break;
        case PR_GET_KEEPCAPS:
            put_ebpf_event_log(event, "get_keepcaps", 13, TYPE_STR);
            break;
        case PR_MCE_KILL:
            put_ebpf_event_log(event, "mce_kill", 9, TYPE_STR);
            break;
        case PR_MCE_KILL_GET:
            put_ebpf_event_log(event, "mce_kill_get", 13, TYPE_STR);
            break;
        case PR_SET_MM:
            put_ebpf_event_log(event, "set_mm", 7, TYPE_STR);
            switch (arg2) {
                case PR_SET_MM_START_CODE:
                    put_ebpf_event_log(event, "set_mm_start_code", 18, TYPE_STR);
                    break;
                case PR_SET_MM_END_CODE:
                    put_ebpf_event_log(event, "set_mm_end_code", 16, TYPE_STR);
                    break;
                case PR_SET_MM_START_DATA:
                    put_ebpf_event_log(event, "set_mm_start_data", 18, TYPE_STR);
                    break;
                case PR_SET_MM_END_DATA:
                    put_ebpf_event_log(event, "set_mm_end_data", 16, TYPE_STR);
                    break;
                case PR_SET_MM_START_STACK:
                    put_ebpf_event_log(event, "set_mm_start_stack", 19, TYPE_STR);
                    break;
                case PR_SET_MM_START_BRK:
                    put_ebpf_event_log(event, "set_mm_start_brk", 17, TYPE_STR);
                    break;
                case PR_SET_MM_BRK:
                    put_ebpf_event_log(event, "set_mm_brk", 11, TYPE_STR);
                    break;
                case PR_SET_MM_ARG_START:
                    put_ebpf_event_log(event, "set_mm_arg_start", 17, TYPE_STR);
                    break;
                case PR_SET_MM_ARG_END:
                    put_ebpf_event_log(event, "set_mm_arg_end", 15, TYPE_STR);
                    break;
                case PR_SET_MM_ENV_START:
                    put_ebpf_event_log(event, "set_mm_env_start", 17, TYPE_STR);
                    break;
                case PR_SET_MM_ENV_END:
                    put_ebpf_event_log(event, "set_mm_env_end", 15, TYPE_STR);
                    break;
                case PR_SET_MM_AUXV:
                    put_ebpf_event_log(event, "set_mm_auxv", 12, TYPE_STR);
                    break;
                case PR_SET_MM_EXE_FILE:
                    put_ebpf_event_log(event, "set_mm_exe_file", 16, TYPE_STR);
                    break;
                case PR_SET_MM_MAP:
                    put_ebpf_event_log(event, "set_mm_map", 11, TYPE_STR);
                    break;
                case PR_SET_MM_MAP_SIZE:
                    put_ebpf_event_log(event, "set_mm_map_size", 16, TYPE_STR);
                    break;
                default:
                    put_ebpf_event_log(event, "unknown", 8, TYPE_STR);
                    lsm_events.ringbuf_submit(event, 0);
                    return -EPERM;
            }
            break;
        // x86
        case PR_MPX_ENABLE_MANAGEMENT:
            put_ebpf_event_log(event, "mpx_enable_management", 22, TYPE_STR);
            break;
        case PR_MPX_DISABLE_MANAGEMENT:
            put_ebpf_event_log(event, "mpx_disable_management", 24, TYPE_STR);
            break;
        case PR_SET_NAME:
            // No need to check, just record
            put_ebpf_event_log(event, "set_name", 9, TYPE_STR);
            char comm[16];
            if (bpf_probe_read_user_str(comm, sizeof(comm), (const char*)arg2) > 0) {
                put_ebpf_event_log(event, comm, ebpf_strnlen(comm, sizeof(comm)), TYPE_STR);
            }
            break;
        case PR_GET_NAME:
            put_ebpf_event_log(event, "get_name", 9, TYPE_STR);
            break;
        case PR_SET_NO_NEW_PRIVS:
            put_ebpf_event_log(event, "set_no_new_privs", 17, TYPE_STR);
            break;
        case PR_GET_NO_NEW_PRIVS:
            put_ebpf_event_log(event, "get_no_new_privs", 17, TYPE_STR);
            break;
        // aarch64
        case PR_PAC_RESET_KEYS:
            put_ebpf_event_log(event, "pac_reset_keys", 15, TYPE_STR);
            break;
        case PR_SET_PDEATHSIG:
            put_ebpf_event_log(event, "set_pdeathsig", 14, TYPE_STR);
            break;
        case PR_GET_PDEATHSIG:
            put_ebpf_event_log(event, "get_pdeathsig", 14, TYPE_STR);
            break;
        case PR_SET_PTRACER:
            put_ebpf_event_log(event, "set_ptracer", 12, TYPE_STR);
            break;
        case PR_SET_SECCOMP:
            put_ebpf_event_log(event, "set_seccomp", 12, TYPE_STR);
            break;
        case PR_GET_SECCOMP:
            put_ebpf_event_log(event, "get_seccomp", 12, TYPE_STR);
            break;
        case PR_SET_SECUREBITS:
            put_ebpf_event_log(event, "set_securebits", 15, TYPE_STR);
            break;
        case PR_GET_SECUREBITS:
            put_ebpf_event_log(event, "get_securebits", 15, TYPE_STR);
            break;
        // x86
        case PR_GET_SPECULATION_CTRL:
            put_ebpf_event_log(event, "get_speculation_ctrl", 21, TYPE_STR);
            break;
        case PR_SET_SPECULATION_CTRL:
            put_ebpf_event_log(event, "set_speculation_ctrl", 21, TYPE_STR);
            break;
        // aarch64
        case PR_SVE_SET_VL:
            put_ebpf_event_log(event, "sve_set_vl", 11, TYPE_STR);
            break;
        case PR_SVE_GET_VL:
            put_ebpf_event_log(event, "sve_get_vl", 11, TYPE_STR);
            break;
        // x86
        case PR_SET_SYSCALL_USER_DISPATCH: 
            put_ebpf_event_log(event, "set_syscall_user_dispatch", 26, TYPE_STR);
            break;
        // aarch64
        case PR_SET_TAGGED_ADDR_CTRL:
            put_ebpf_event_log(event, "set_tagged_addr_ctrl", 23, TYPE_STR);
            break;
        case PR_GET_TAGGED_ADDR_CTRL:
            put_ebpf_event_log(event, "get_tagged_addr_ctrl", 23, TYPE_STR);
            break;
        case PR_TASK_PERF_EVENTS_DISABLE:
            put_ebpf_event_log(event, "task_perf_events_disable", 29, TYPE_STR);
            break;
        case PR_TASK_PERF_EVENTS_ENABLE:
            put_ebpf_event_log(event, "task_perf_events_enable", 27, TYPE_STR);
            break;
        case PR_SET_THP_DISABLE:
            put_ebpf_event_log(event, "set_thp_disable", 16, TYPE_STR);
            break;
        case PR_GET_THP_DISABLE:
            put_ebpf_event_log(event, "get_thp_disable", 16, TYPE_STR);
            break;
        case PR_GET_TID_ADDRESS:
            put_ebpf_event_log(event, "get_tid_address", 18, TYPE_STR);
            break;
        case PR_SET_TIMERSLACK:
            put_ebpf_event_log(event, "set_timerslack", 17, TYPE_STR);
            break;
        case PR_GET_TIMERSLACK:
            put_ebpf_event_log(event, "get_timerslack", 17, TYPE_STR);
            break;
        case PR_SET_TIMING:
            put_ebpf_event_log(event, "set_timing", 11, TYPE_STR);
            break;
        case PR_GET_TIMING:
            put_ebpf_event_log(event, "get_timing", 11, TYPE_STR);
            break;
        case PR_GET_TSC:
            put_ebpf_event_log(event, "get_tsc", 8, TYPE_STR);
            break;
        case PR_SET_TSC:
            put_ebpf_event_log(event, "set_tsc", 8, TYPE_STR);
            break;
        case PR_SET_UNALIGN:
            put_ebpf_event_log(event, "set_unalign", 12, TYPE_STR);
            break;
        case PR_GET_UNALIGN:
            put_ebpf_event_log(event, "get_unalign", 12, TYPE_STR);
            break;
        default:
            put_ebpf_event_log(event, "unknown", 8, TYPE_STR);
            lsm_events.ringbuf_submit(event, 0);
            return -EPERM;
    }

    lsm_events.ringbuf_submit(event, 0);
    return 0;
}



/// @brief 
/// @param  
/// @param p 
LSM_PROBE(task_movememory, struct task_struct *p) {
    return -EPERM;
}



/// @brief 
/// @param  
/// @param p 
/// @param inode 
LSM_PROBE(task_to_inode, struct task_struct *p, struct inode *inode) {
    return 0;
}


/// @brief Protect configured task avoid be traced, this is not like shield ptrace protect it is configurable
/// @param  
/// @param child 
/// @param mode 
LSM_PROBE(ptrace_access_check, struct task_struct *child, unsigned int mode) {
    struct task_info task_comm;
    ebpf_memset(task_comm.comm, 0, sizeof(task_comm.comm));
    if (ebpf_get_task_app_name(child, task_comm.comm, sizeof(task_comm.comm)) != 0) {
        return -EACCES;
    }

    if (task_ptrace_protect.lookup(&task_comm) != NULL) {
        struct ebpf_event *event = lsm_events.ringbuf_reserve(sizeof(struct ebpf_event));
        if (event == NULL) {
            return -EPERM;
        }
        initialize_ebpf_event_log(event, "ptrace_access_check");
        put_ebpf_event_log(event, "protect_ptrace", 15, TYPE_STR);
        put_ebpf_event_log(event, task_comm.comm, ebpf_strnlen(task_comm.comm, sizeof(task_comm.comm)), TYPE_STR);
        
        if (ebpf_get_current_task_app_name(task_comm.comm, sizeof(task_comm.comm)) == 0) {
            put_ebpf_event_log(event, "from", 5, TYPE_STR);
            put_ebpf_event_log(event, task_comm.comm, ebpf_strnlen(task_comm.comm, sizeof(task_comm.comm)), TYPE_STR);
        }

        lsm_events.ringbuf_submit(event, 0);

        return -EPERM;
    }

    return 0;
}

/// @brief Protect configured task avoid be traced, this is not like shield ptrace protect it is configurable
/// @param  
/// @param parent 
LSM_PROBE(ptrace_traceme, struct task_struct *parent) {
    struct task_info task_comm;
    ebpf_memset(task_comm.comm, 0, sizeof(task_comm.comm));
    if (ebpf_get_current_task_app_name(task_comm.comm, sizeof(task_comm.comm)) != 0) {
        return -EACCES;
    }

    if (task_ptrace_protect.lookup(&task_comm) != NULL) {
        struct ebpf_event *event = lsm_events.ringbuf_reserve(sizeof(struct ebpf_event));
        if (event == NULL) {
            return -EPERM;
        }

        initialize_ebpf_event_log(event, "ptrace_traceme");
        put_ebpf_event_log(event, "protect_traceme", 16, TYPE_STR);
        put_ebpf_event_log(event, task_comm.comm, ebpf_strnlen(task_comm.comm, sizeof(task_comm.comm)), TYPE_STR);
        lsm_events.ringbuf_submit(event, 0);

        return -EPERM;
    }

    return 0;
}