// SPDX-License-Identifier: 2023
// Copyright Alex Zhao
//
// eBPF based Security Module
//  binary executable direct security check
//
#include <linux/sched.h>
#include <linux/binfmts.h>
#include <linux/errno.h>
#include <linux/cred.h>

#include "ebpf/ebpf_file.h"
#include "ebpf/ebpf_event.h"
#include "ebpf/ebpf_str.h"
#include "ebpf/ebpf_exe.h"

BPF_RINGBUF_OUTPUT(lsm_events, 8);

// simple comm to identify task, it shall use task_struct with 
// executable file and credential
struct task_info {
    char comm[16];
};

BPF_HASH(app_block_list, struct task_info, u32);

#define MAXIMUM_LEN_OF_APP_ALLOW_LIST 32

BPF_HASH(initiate_task_list, struct task_info, u32, MAXIMUM_LEN_OF_APP_ALLOW_LIST);
BPF_HASH(initiate_task_list_1, struct task_info, u32, MAXIMUM_LEN_OF_APP_ALLOW_LIST);
BPF_HASH(initiate_task_list_2, struct task_info, u32, MAXIMUM_LEN_OF_APP_ALLOW_LIST);
BPF_HASH(initiate_task_list_3, struct task_info, u32, MAXIMUM_LEN_OF_APP_ALLOW_LIST);
BPF_HASH(initiate_task_list_4, struct task_info, u32, MAXIMUM_LEN_OF_APP_ALLOW_LIST);

BPF_HASH_OF_MAPS(app_allow_list, struct task_info, "initiate_task_list", MAXIMUM_LEN_OF_APP_ALLOW_LIST);

// Basic Execve access control,
// credential
// block/allow list comparsion
LSM_PROBE(bprm_check_security, struct linux_binprm *bprm) {
    struct task_info app;

    ebpf_memset(app.comm, 0, sizeof(app.comm));
    if (ebpf_get_file_name(bprm->file, app.comm, sizeof(app.comm)) < 0) {
        return -EACCES;
    }

    if (app_block_list.lookup(&app) != NULL) {
        struct ebpf_event *event = lsm_events.ringbuf_reserve(sizeof(struct ebpf_event));
        if (event != NULL) {
            initialize_ebpf_event_log(event, "bprm_check_security");            
            put_ebpf_event_log(event, "block_app", 10, TYPE_STR);
            put_ebpf_event_log(event, (const char *)app.comm, ebpf_strnlen(app.comm, sizeof(app.comm)), TYPE_STR);

            char app_name[32];
            ebpf_get_current_task_app_name(app_name, sizeof(app_name));
            put_ebpf_event_log(event, (const char *)app_name, ebpf_strnlen(app_name, sizeof(app_name)), TYPE_STR);
            lsm_events.ringbuf_submit(event, 0);
        }

        return -EPERM;
    }
    
    void *allow_app_entry = app_allow_list.lookup(&app);
    if (allow_app_entry != NULL) {
        struct ebpf_event *event = lsm_events.ringbuf_reserve(sizeof(struct ebpf_event));
        if (event == NULL) {
            return -EACCES;
        }
        initialize_ebpf_event_log(event, "bprm_check_security");
        put_ebpf_event_log(event, "block_app", 10, TYPE_STR);
        put_ebpf_event_log(event, (const char *)app.comm, ebpf_strnlen(app.comm, sizeof(app.comm)), TYPE_STR);

        ebpf_memset(app.comm, 0, sizeof(app.comm));
        if (ebpf_get_current_task_app_name(app.comm, sizeof(app.comm)) == 0) {
            void *entry = bpf_map_lookup_elem(allow_app_entry, &app);
            if (entry != NULL) {
                lsm_events.ringbuf_discard(event, 0);
                return 0;
            } else {
                put_ebpf_event_log(event, (const char *)app.comm, ebpf_strnlen(app.comm, sizeof(app.comm)), TYPE_STR);
                lsm_events.ringbuf_submit(event, 0);
                return -EPERM;
            }
        } else {
            lsm_events.ringbuf_discard(event, 0);
            return -EPERM;
        }
    }

    struct ebpf_event *event = lsm_events.ringbuf_reserve(sizeof(struct ebpf_event));
    if (event != NULL) {
        initialize_ebpf_event_log(event, "bprm_check_security");
        put_ebpf_event_log(event, "allow_app", 10, TYPE_STR);
        put_ebpf_event_log(event, (const char *)app.comm, ebpf_strnlen(app.comm, sizeof(app.comm)), TYPE_STR);
        
        char app_name[32];
        ebpf_get_current_task_app_name(app_name, sizeof(app_name));
        put_ebpf_event_log(event, (const char *)app_name, ebpf_strnlen(app_name, sizeof(app_name)), TYPE_STR);
        lsm_events.ringbuf_submit(event, 0);
    }

    return 0;
}

LSM_PROBE(bprm_creds_for_exec, struct linux_binprm *bprm) {
    return 0;
}

LSM_PROBE(bprm_creds_from_file, struct linux_binprm *bprm, struct file *file) {
    return 0;
}


