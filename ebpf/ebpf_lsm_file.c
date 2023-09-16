// SPDX-License-Identifier: 2023
// Copyright Zhao Zhe (Alex)
//
// eBPF based Security Module
//  file based protection
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/errno.h>

#include <linux/mman.h>
#include <linux/mm.h>
#include <linux/mm_types.h>

#include "ebpf/ebpf_event.h"
#include "ebpf/ebpf_exe.h"
#include "ebpf/ebpf_file.h"
#include "ebpf/ebpf_str.h"

BPF_RINGBUF_OUTPUT(lsm_events, 8);

// simple comm to identify task, it shall use task_struct with 
// executable file and credential
struct task_info {
    char comm[16];
};

struct dev_info {
    char devname[32];
};


#define MAXIMUM_LEN_OF_APP_ACCESS_LIST  8
#define MAXIMUM_LEN_OF_DEV_ACCESS_LIST  16


BPF_HASH(block_ioctl_list, struct dev_info, u32, MAXIMUM_LEN_OF_DEV_ACCESS_LIST);
BPF_HASH(block_ioctl_list_1, struct dev_info, u32, MAXIMUM_LEN_OF_DEV_ACCESS_LIST);
BPF_HASH(block_ioctl_list_2, struct dev_info, u32, MAXIMUM_LEN_OF_DEV_ACCESS_LIST);
BPF_HASH(block_ioctl_list_3, struct dev_info, u32, MAXIMUM_LEN_OF_DEV_ACCESS_LIST);
BPF_HASH(block_ioctl_list_4, struct dev_info, u32, MAXIMUM_LEN_OF_DEV_ACCESS_LIST);
BPF_HASH(block_ioctl_list_5, struct dev_info, u32, MAXIMUM_LEN_OF_DEV_ACCESS_LIST);
BPF_HASH(block_ioctl_list_6, struct dev_info, u32, MAXIMUM_LEN_OF_DEV_ACCESS_LIST);
BPF_HASH(block_ioctl_list_7, struct dev_info, u32, MAXIMUM_LEN_OF_DEV_ACCESS_LIST);

BPF_HASH_OF_MAPS(app_block_ioctl_list, struct task_info, "block_ioctl_list", MAXIMUM_LEN_OF_APP_ACCESS_LIST);


struct file_info {
    char name[32];
};


BPF_HASH(allow_file_open_list, struct task_info, u32, MAXIMUM_LEN_OF_DEV_ACCESS_LIST);
BPF_HASH(allow_file_open_list_1, struct task_info, u32, MAXIMUM_LEN_OF_DEV_ACCESS_LIST);
BPF_HASH(allow_file_open_list_2, struct task_info, u32, MAXIMUM_LEN_OF_DEV_ACCESS_LIST);
BPF_HASH(allow_file_open_list_3, struct task_info, u32, MAXIMUM_LEN_OF_DEV_ACCESS_LIST);
BPF_HASH(allow_file_open_list_4, struct task_info, u32, MAXIMUM_LEN_OF_DEV_ACCESS_LIST);

// filename config associated allow access list
BPF_HASH_OF_MAPS(file_block_list, struct file_info, "allow_file_open_list", MAXIMUM_LEN_OF_APP_ACCESS_LIST);

/// @brief  Security Control of Open file, when initiator is python, bash, ... it may interperate executable file
/// @param  
/// @param file 
LSM_PROBE(file_open, struct file *file) {
    struct file_info file_name;

    ebpf_memset(file_name.name, 0, sizeof(file_name.name));
    if (ebpf_get_file_name(file, file_name.name, sizeof(file_name.name)) != 0) {
        return -EACCES;
    }

    void *file_block_list_entry = NULL;
    file_block_list_entry = file_block_list.lookup(&file_name);
    if (file_block_list_entry == NULL) {
        return 0;
    }

    struct task_info app_name;
    ebpf_memset(app_name.comm, 0, sizeof(app_name.comm));
    if (ebpf_get_current_task_app_name(app_name.comm, sizeof(app_name.comm)) != 0) {
        return -EACCES;
    }

    void *entry = NULL;
    entry = bpf_map_lookup_elem(file_block_list_entry, &app_name);
    if (entry == NULL) {
        struct ebpf_event *event = lsm_events.ringbuf_reserve(sizeof(struct ebpf_event));
        if (event != NULL) {
            initialize_ebpf_event_log(event, "file_open");
            put_ebpf_event_log(event, "open_reject", 12, TYPE_STR);
            put_ebpf_event_log(event, file_name.name, ebpf_strnlen(file_name.name, sizeof(file_name.name)), TYPE_STR);
            put_ebpf_event_log(event, app_name.comm, ebpf_strnlen(app_name.comm, sizeof(app_name.comm)), TYPE_STR);
            lsm_events.ringbuf_submit(event, 0);
        }

        return -EPERM;
    }

    return 0;
}

/// @brief For some file not allow to increase the priority
///        from r -> w, w -> x this type of modification
/// @param  
/// @param file 
/// @param mask 
LSM_PROBE(file_permission, struct file *file, int mask) {
    

    return 0;
}

/// @brief  Security Control Device IOCTL, direct cause GUI crash, many basic gui related 
///          service access ioctl
/// @param  
/// @param file 
/// @param cmd 
/// @param arg 
LSM_PROBE(file_ioctl, struct file *file, unsigned int cmd, unsigned long arg) {
    struct task_info app_name;
    ebpf_memset(app_name.comm, 0, sizeof(app_name.comm));
    if (ebpf_get_current_task_app_name(app_name.comm, sizeof(app_name.comm)) != 0) {
        return -EACCES;
    }

    void *app_block_list = NULL;
    app_block_list = app_block_ioctl_list.lookup(&app_name);
    if (app_block_list == NULL) {
        return 0;
    }

    struct path ioctl_file_path;
    if (bpf_probe_read_kernel(&ioctl_file_path, sizeof(ioctl_file_path), &file->f_path) != 0) {
        return -EACCES;
    }

    struct qstr ioctl_name;
    if (bpf_probe_read_kernel(&ioctl_name, sizeof(ioctl_name), &ioctl_file_path.dentry->d_name) != 0) {
        return -EACCES;
    }

    struct dev_info devname;
    ebpf_memset(devname.devname, 0, sizeof(devname.devname));
    if (bpf_probe_read_kernel_str(devname.devname, sizeof(devname.devname), ioctl_name.name) < 0) {
        return -EACCES;
    }

    // Check from app to access which device
    void *entry = NULL;
    entry = bpf_map_lookup_elem(app_block_list, &devname);
    if (entry == NULL) {
        return 0;
    }

    struct ebpf_event *event = lsm_events.ringbuf_reserve(sizeof(struct ebpf_event));
    if (event != NULL) {
        initialize_ebpf_event_log(event, "file_ioctl");
        put_ebpf_event_log(event, "ioctl_reject", 13, TYPE_STR);
        put_ebpf_event_log(event, app_name.comm, ebpf_strnlen(app_name.comm, sizeof(app_name.comm)), TYPE_STR);
        put_ebpf_event_log(event, devname.devname, ebpf_strnlen(devname.devname, sizeof(devname.devname)), TYPE_STR);
        lsm_events.ringbuf_submit(event, 0);
    }

    return -EPERM;
}



/// @brief 
/// @param  
/// @param addr 
LSM_PROBE(mmap_addr, unsigned long addr) {
    return 0;
}



/// @brief 
/// @param  
/// @param file 
LSM_PROBE(file_alloc_security, struct file *file) {
    return 0;
}



/// @brief 
/// @param  
/// @param file 
/// @param cmd 
LSM_PROBE(file_lock, struct file *file, unsigned int cmd) {
    return 0;
}




/// @brief 
/// @param  
/// @param file 
/// @param cmd 
/// @param arg 
LSM_PROBE(file_fcntl, struct file *file, unsigned int cmd,
	 unsigned long arg) {
    return 0;
}

/// @brief check mapped file protection attribute extra
///        A kernel level ld-linux mapping check
/// @param  
/// @param file 
/// @param prot 
/// @param flags 
LSM_PROBE(mmap_file, struct file *file, unsigned long prot, unsigned long flags) {    
    // anon mem with not W+X, direct allow
    if (file == NULL && !((prot & PROT_WRITE) && (prot & PROT_EXEC))) {
        return 0;
    }

    // readonly, direct allow
    if ((prot & PROT_READ) && !((prot & PROT_WRITE) || (prot & PROT_EXEC))) {
        return 0;
    }

    struct task_info app_name;
    ebpf_memset(app_name.comm, 0, sizeof(app_name.comm));
    if (ebpf_get_current_task_app_name(app_name.comm, sizeof(app_name.comm)) != 0) {
        return -EACCES;
    }

    struct file_info file_name;
    ebpf_memset(file_name.name, 0, sizeof(file_name.name));
    if (file != NULL) {
        if (ebpf_get_file_name(file, file_name.name, sizeof(file_name.name)) != 0) {
            ebpf_strncpy(file_name.name, "Failed", 7);
        }
    } else {
        ebpf_strncpy(file_name.name, "NULL", 5);
    }

    char prot_attr[4];
    char *pos = prot_attr;
    ebpf_memset(prot_attr, 0, sizeof(prot_attr));
    if (prot & PROT_READ) {
        *pos++ = 'r';
    }
    
    if (prot & PROT_WRITE) {
        *pos++ = 'w';
    }

    if (prot & PROT_EXEC) {
        *pos++ = 'x';
    }

    struct ebpf_event *event = lsm_events.ringbuf_reserve(sizeof(struct ebpf_event));
    if (event != NULL) {
        initialize_ebpf_event_log(event, "mmap_file");
        put_ebpf_event_log(event, prot_attr, ebpf_strnlen(prot_attr, sizeof(prot_attr)), TYPE_STR);
        put_ebpf_event_log(event, app_name.comm, ebpf_strnlen(app_name.comm, sizeof(app_name.comm)), TYPE_STR);
        put_ebpf_event_log(event, file_name.name, ebpf_strnlen(file_name.name, sizeof(file_name.name)), TYPE_STR);
        lsm_events.ringbuf_submit(event, 0);
    }

    return 0;
}

#define READ_INCREMENT 1
#define WRITE_INCREMENT 2
#define EXEC_INCREMENT 4
/// @brief Check the modification of memory protection attributes
///        X86 Protection key example:
/// struct vm_area_struct {
///     ...
///    	pgprot_t vm_page_prot;
///
/// 	/*
/// 	 * Flags, see mm.h.
/// 	 * To modify use vm_flags_{init|reset|set|clear|mod} functions.
/// 	 */
/// 	union {
/// 		const vm_flags_t vm_flags;
/// 		vm_flags_t __private __vm_flags;
/// 	};
///     ...
/// }
///
/// static pgprot_t protection_map[16] __ro_after_init = {
/// 	[VM_NONE]					= PAGE_NONE,
/// 	[VM_READ]					= PAGE_READONLY,
/// 	[VM_WRITE]					= PAGE_COPY,
/// 	[VM_WRITE | VM_READ]				= PAGE_COPY,
/// 	[VM_EXEC]					= PAGE_READONLY_EXEC,
/// 	[VM_EXEC | VM_READ]				= PAGE_READONLY_EXEC,
/// 	[VM_EXEC | VM_WRITE]				= PAGE_COPY_EXEC,
/// 	[VM_EXEC | VM_WRITE | VM_READ]			= PAGE_COPY_EXEC,
/// 	[VM_SHARED]					= PAGE_NONE,
/// 	[VM_SHARED | VM_READ]				= PAGE_READONLY,
/// 	[VM_SHARED | VM_WRITE]				= PAGE_SHARED,
/// 	[VM_SHARED | VM_WRITE | VM_READ]		= PAGE_SHARED,
/// 	[VM_SHARED | VM_EXEC]				= PAGE_READONLY_EXEC,
/// 	[VM_SHARED | VM_EXEC | VM_READ]			= PAGE_READONLY_EXEC,
/// 	[VM_SHARED | VM_EXEC | VM_WRITE]		= PAGE_SHARED_EXEC,
/// 	[VM_SHARED | VM_EXEC | VM_WRITE | VM_READ]	= PAGE_SHARED_EXEC
/// };
/// @param  
/// @param vma 
/// @param reqprot 
/// @param prot 
LSM_PROBE(file_mprotect, struct vm_area_struct *vma, unsigned long reqprot,
			   unsigned long prot) {
    vm_flags_t vmflag  = vma->vm_flags;

    struct task_info app_name;
    ebpf_memset(app_name.comm, 0, sizeof(app_name.comm));
    if (ebpf_get_current_task_app_name(app_name.comm, sizeof(app_name.comm)) != 0) {
        return -EACCES;
    } else {
        // Not able to track to the application with firefox
        if (bpf_get_current_comm(app_name.comm, sizeof(app_name.comm)) != 0) {
            ebpf_strncpy(app_name.comm, "UNKNOWN", 8);
        }
    }

    char modify[20];
    ebpf_memset(modify, 0 ,sizeof(modify));
    char *m = modify;

    int from = 0;
    if (vmflag & VM_READ) {
        *m++ = 'r';
        from += READ_INCREMENT;
    }

    if (vmflag & VM_WRITE) {
        *m++ = 'w';
        from += WRITE_INCREMENT;
    }

    if (vmflag & VM_EXEC) {
        *m++ = 'x';
        from += EXEC_INCREMENT;
    }

    *m++ = '-';
    *m++ = '>';

    int to = 0;
    if (prot & PROT_READ) {
        *m++ = 'r';
        to += READ_INCREMENT;
    }

    if (prot & PROT_WRITE) {
        *m++ = 'w';
        to += WRITE_INCREMENT;
    }

    if (prot & PROT_EXEC) {
        *m++ = 'x';
        to += EXEC_INCREMENT;
    }

    // many rx->rw, and rw->rx modification
    // JIT, ....
    if (to - from <= 0) {
        return 0;
    }

    struct ebpf_event *event = lsm_events.ringbuf_reserve(sizeof(struct ebpf_event));
    if (event != NULL) {
        initialize_ebpf_event_log(event, "file_mprotect");
        put_ebpf_event_log(event, modify, ebpf_strnlen(modify, sizeof(modify)), TYPE_STR);
        put_ebpf_event_log(event, app_name.comm, ebpf_strnlen(app_name.comm, sizeof(app_name.comm)), TYPE_STR);
        
        struct file *f = vma->vm_file;
        if (f) {
            struct file_info file_name;
            ebpf_memset(file_name.name, 0, sizeof(file_name.name));
            if (ebpf_get_file_name(f, file_name.name, sizeof(file_name.name)) != 0) {
                lsm_events.ringbuf_discard(event, 0);
                return 0;
            }
            put_ebpf_event_log(event, file_name.name, ebpf_strnlen(file_name.name, sizeof(file_name.name)), TYPE_STR);
        }

        lsm_events.ringbuf_submit(event, 0);
    }

    return 0;
}

/// @brief 
/// @param  
/// @param tsk 
/// @param fown 
/// @param sig 
LSM_PROBE(file_send_sigiotask, struct task_struct *tsk,
	 struct fown_struct *fown, int sig) {

    return 0;
}



/// @brief 
/// @param  
/// @param file 
LSM_PROBE(file_receive, struct file *file) {
    return 0;
}




/// @brief 
/// @param  
/// @param file 
LSM_PROBE(file_truncate, struct file *file) {
    return 0;
}
