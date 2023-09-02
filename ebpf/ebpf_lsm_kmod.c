// SPDX-License-Identifier: 2023
// Copyright Zhao Zhe (Alex)
//
// eBPF based Security Module
//  module loading protection
#include <linux/security.h>
#include <linux/kernel_read_file.h>
#include <linux/module.h>
#include <linux/kernfs.h>
#include <linux/cred.h>

#include "ebpf/ebpf_event.h"
#include "ebpf/ebpf_str.h"
#include "ebpf/ebpf_intf.h"
#include "ebpf/ebpf_file.h"

BPF_RINGBUF_OUTPUT(lsm_events, 8);

BPF_HASH(allow_kmod_list, struct kmod, u32);
BPF_HASH(allow_attach_dev_list, struct kmod, u32);



/// @brief 
/// @param  
/// @param  
/// @param secid 
LSM_PROBE(kernel_act_as, struct cred *new, u32 secid) {
    return 0;
}



/// @brief Security Control of Kernel load, without signature kmod_name is 
///        easy to bypass
/// @param  
/// @param kmod_name 
LSM_PROBE(kernel_module_request, char *kmod_name) {
    struct ebpf_event *event = lsm_events.ringbuf_reserve(sizeof(struct ebpf_event));
    if (event == NULL) {
        return -EPERM;
    }
    initialize_ebpf_event_log(event, "kernel_module_request");

    char kmod[MODULE_NAME_LEN];
    if (bpf_probe_read_kernel_str(kmod, sizeof(kmod), kmod_name) < 0) {
        lsm_events.ringbuf_discard(event, 0);
        return -EPERM;
    }
    put_ebpf_event_log(event, "kmod_request", 13, TYPE_STR);
    put_ebpf_event_log(event, kmod, ebpf_strnlen(kmod, sizeof(kmod)), TYPE_STR);

    lsm_events.ringbuf_submit(event, 0);

    return 0;
}

#define MODULE_KN_NAME "module"


/// @brief  Block create sysfs entry point to block loading kernel mod, and other kernel behavior, the hook point after kmod version check and symbol resolve
/// @param  
/// @param kn_dir 
/// @param kn 
LSM_PROBE(kernfs_init_security, struct kernfs_node *kn_dir, struct kernfs_node *kn) {
    struct ebpf_event *event = lsm_events.ringbuf_reserve(sizeof(struct ebpf_event));
    if (event == NULL) {
        return -EPERM;
    }
    initialize_ebpf_event_log(event, "kernfs_init_security");

    struct kmod kmod_name;
    ebpf_memset(kmod_name.name, 0, sizeof(kmod_name.name));
    if (bpf_probe_read_kernel_str(kmod_name.name, sizeof(kmod_name.name), kn_dir->name) < 0) {
        put_ebpf_event_log(event, "failed_load_kn_dir", 19, TYPE_STR);
        lsm_events.ringbuf_submit(event, 0);
        return 0;
    }

    if (ebpf_strncmp(kmod_name.name, MODULE_KN_NAME, 7) != 0) {
        lsm_events.ringbuf_discard(event, 0);
        return 0;
    }

    put_ebpf_event_log(event, kmod_name.name, ebpf_strnlen(kmod_name.name, sizeof(kmod_name.name)), TYPE_STR);

    ebpf_memset(kmod_name.name, 0, sizeof(kmod_name.name));
    if (bpf_probe_read_kernel_str(kmod_name.name, sizeof(kmod_name.name), kn->name) < 0) {
        lsm_events.ringbuf_discard(event, 0);
        return -EPERM;
    }

    if (allow_kmod_list.lookup(&kmod_name)) {
        lsm_events.ringbuf_discard(event, 0);
        return 0;
    }

    put_ebpf_event_log(event, kmod_name.name, ebpf_strnlen(kmod_name.name, sizeof(kmod_name.name)), TYPE_STR);
    lsm_events.ringbuf_submit(event, 0);
    return -EPERM;
}

/// @brief 
/// @param  
/// @param  
/// @param contents 
LSM_PROBE(kernel_load_data, enum kernel_load_data_id id, bool contents) {
    return 0;
}



/// @brief 
/// @param  
/// @param buf 
/// @param size 
/// @param  
/// @param description 
LSM_PROBE(kernel_post_load_data, char *buf, loff_t size,
	 enum kernel_load_data_id id, char *description) {

    return 0;
}



#define KO_SUFFIX_LEN 4

/// @brief Blocking kmod loading kernel read file
/// @param  
/// @param file 
/// @param  
/// @param contents 
LSM_PROBE(kernel_read_file, struct file *file, enum kernel_read_file_id id, bool contents) {
    // Block Kernel mod loading
    char kmod_name[32];
    ebpf_memset(kmod_name, 0, sizeof(kmod_name));
    if (ebpf_get_file_name(file, kmod_name, sizeof(kmod_name)) < 0) {
        return -EACCES;
    }

    int str_len = ebpf_strnlen(kmod_name, sizeof(kmod_name));
    if (str_len < 0 || str_len > sizeof(kmod_name)) {
        return -EACCES;
    }
    str_len = str_len - KO_SUFFIX_LEN;
    if (str_len > 0)
        kmod_name[str_len] = 0;
    else
        return -EACCES;

    struct kmod kmod_n;
    ebpf_memset(kmod_n.name, 0, sizeof(kmod_n.name));
    ebpf_strncpy(kmod_n.name, kmod_name, sizeof(kmod_n.name));

    if (allow_kmod_list.lookup(&kmod_n)) {
        return 0;
    } else {
        struct ebpf_event *event = lsm_events.ringbuf_reserve(sizeof(struct ebpf_event));
        if (event) {
            initialize_ebpf_event_log(event, "kernel_read_file");
            put_ebpf_event_log(event, "block_kmod_load", 18, TYPE_STR);
            put_ebpf_event_log(event, kmod_n.name, ebpf_strnlen(kmod_n.name, sizeof(kmod_n.name)), TYPE_STR);
            lsm_events.ringbuf_submit(event, 0);
        }
    }

    return -EPERM;
}


/// @brief 
/// @param  
/// @param file 
/// @param buf 
/// @param size 
/// @param  
LSM_PROBE(kernel_post_read_file, struct file *file, char *buf,
	 loff_t size, enum kernel_read_file_id id) {

    return 0;
}


/// @brief 
/// @param  
/// @param  
/// @param inode 
LSM_PROBE(kernel_create_files_as, struct cred *new, struct inode *inode) {
    return 0;
}