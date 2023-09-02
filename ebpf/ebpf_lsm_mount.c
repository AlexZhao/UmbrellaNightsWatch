// SPDX-License-Identifier: 2023
// Copyright Zhao Zhe (Alex)
//
// eBPF based Security Module
// mount point and device control
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/errno.h>
#include <linux/mtd/mtd.h>

#include "ebpf/ebpf_event.h"
#include "ebpf/ebpf_exe.h"
#include "ebpf/ebpf_str.h"

BPF_RINGBUF_OUTPUT(lsm_events, 8);

#define MAXIMUM_FOLDER 128 

struct folder {
    char name[64];
};

BPF_HASH(blocked_mnt_src, struct folder, u32, MAXIMUM_FOLDER);


#define MAXIMUM_PATH_LEN 256

/// @brief  Security Control for move_mount which can be used to replace existed 
///         contents
/// @param  
/// @param from_path 
/// @param to_path 
LSM_PROBE(move_mount, const struct path *from_path, const struct path *to_path) {
    struct dentry *from_entry = NULL;
    struct dentry *to_entry = NULL;
    if (bpf_probe_read_kernel(&from_entry, sizeof(from_entry), &from_path->dentry) != 0) {
        return -EACCES;
    }

    if (bpf_probe_read_kernel(&to_entry, sizeof(to_entry), &to_path->dentry) != 0) {
        return -EACCES;
    }

    struct ebpf_event *event = lsm_events.ringbuf_reserve(sizeof(struct ebpf_event));
    if (event == NULL) {
        return -EACCES;
    }
    initialize_ebpf_event_log(event, "move_mount");

    struct exec_file_path *cur_exec_file_path = NULL;
    int key = 0;
    cur_exec_file_path = cur_exe_file_path_array.lookup(&key);
    if (cur_exec_file_path == NULL) {
        lsm_events.ringbuf_discard(event, 0);
        return -EPERM;
    }

    if (ebpf_get_path(from_entry, cur_exec_file_path) == 0) {
        for (int i = cur_exec_file_path->depth - 1; i >= 0; i--) {
            put_ebpf_event_log(event, cur_exec_file_path->path[i], ebpf_strnlen(cur_exec_file_path->path[i], sizeof(cur_exec_file_path->path[i])), TYPE_STR);
        }
    } else {
        lsm_events.ringbuf_discard(event, 0);
        return -EPERM;
    }

    if (ebpf_get_path(to_entry, cur_exec_file_path) == 0) {
        for (int i = cur_exec_file_path->depth - 1; i >= 0; i--) {
            //put_ebpf_event_log(event, cur_exec_file_path->path[i], ebpf_strnlen(cur_exec_file_path->path[i], sizeof(cur_exec_file_path->path[i])), TYPE_STR);
        }
    } else {
        lsm_events.ringbuf_discard(event, 0);
        return -EPERM;
    }

    lsm_events.ringbuf_submit(event, 0);
    return 0;
}

/// @brief Security Control for mount device
/// @param  
/// @param dev_name 
/// @param path 
/// @param type 
/// @param flags 
/// @param data 
LSM_PROBE(sb_mount, const char *dev_name, const struct path *path,
		      const char *type, unsigned long flags, void *data) {
    struct dentry *to_entry = NULL;
    struct ebpf_event *event = lsm_events.ringbuf_reserve(sizeof(struct ebpf_event));
    if (event == NULL) {
        return -EACCES;
    }
    initialize_ebpf_event_log(event, "sb_mount");
    char comm[16];
    if (ebpf_get_current_task_app_name(comm, sizeof(comm)) != 0) {
        lsm_events.ringbuf_discard(event, 0);
        return -EACCES;
    }
    put_ebpf_event_log(event, comm, sizeof(comm), TYPE_STR);

    char temp_path[MAXIMUM_PATH_LEN];
    if (dev_name != NULL) {
        ebpf_memset(temp_path, 0, sizeof(temp_path));
        if (bpf_probe_read_kernel_str(temp_path, sizeof(temp_path), dev_name) < 0) {
            // NOTICE: not mandatory required, dev_name can be NULL
            put_ebpf_event_log(event, "failed_load_dev_name", 23, TYPE_STR);
            lsm_events.ringbuf_submit(event, 0);
            return 0;
        }
        put_ebpf_event_log(event, temp_path, ebpf_strnlen(temp_path, sizeof(temp_path)), TYPE_STR);
    } else {
        put_ebpf_event_log(event, "NULL", 5, TYPE_STR);
    }

    if (bpf_probe_read_kernel(&to_entry, sizeof(to_entry), &path->dentry) != 0) {
        put_ebpf_event_log(event, "failed_load_to", 15, TYPE_STR);
        lsm_events.ringbuf_submit(event, 0);
        return 0;
    }

    struct exec_file_path *cur_exec_file_path = NULL;
    int key = 0;
    cur_exec_file_path = cur_exe_file_path_array.lookup(&key);
    if (cur_exec_file_path == NULL) {
        lsm_events.ringbuf_discard(event, 0);
        return -EPERM;
    }

    if (ebpf_get_path(to_entry, cur_exec_file_path) == 0) {
        for (int i = cur_exec_file_path->depth - 1; i >= 0; i--) {
            put_ebpf_event_log(event, cur_exec_file_path->path[i], ebpf_strnlen(cur_exec_file_path->path[i], sizeof(cur_exec_file_path->path[i])), TYPE_STR);
        }
    } else {
        put_ebpf_event_log(event, "failed_load_file", 17, TYPE_STR);
        lsm_events.ringbuf_submit(event, 0);
        return 0;
    }

    ebpf_memset(temp_path, 0, sizeof(temp_path));
    if (bpf_probe_read_kernel_str(temp_path, sizeof(temp_path), type) > 0) {
        put_ebpf_event_log(event, temp_path, ebpf_strnlen(temp_path, sizeof(temp_path)), TYPE_STR);
    }

    lsm_events.ringbuf_submit(event, 0);    
    return 0;
}


/// @brief remount mount pointer, remount will able to remount ro filesystem to rw
/// @param  
/// @param sb 
/// @param mnt_opts 
LSM_PROBE(sb_remount, struct super_block *sb, void *mnt_opts) {
    struct ebpf_event *event = lsm_events.ringbuf_reserve(sizeof(struct ebpf_event));
    if (event == NULL) {
        return -EACCES;
    }
    initialize_ebpf_event_log(event, "sb_remount");

    char tmp_name[32];
    if (sb->s_root != NULL) {
        struct dentry *s_root = sb->s_root;
        struct qstr name;
        if (bpf_probe_read_kernel(&name, sizeof(name), &s_root->d_name) == 0) {
            if (bpf_probe_read_kernel_str(tmp_name, sizeof(tmp_name), name.name) > 0) {
                put_ebpf_event_log(event, tmp_name, ebpf_strnlen(tmp_name, sizeof(tmp_name)), TYPE_STR);
            }
        }
    }

    if (bpf_probe_read_kernel_str(tmp_name, sizeof(tmp_name), sb->s_id) > 0) {
        put_ebpf_event_log(event, tmp_name, ebpf_strnlen(tmp_name, sizeof(tmp_name)), TYPE_STR);
    }

    if (sb->s_mtd != NULL) {
        struct mtd_info *s_mtd = sb->s_mtd;
        char *name = NULL;
        if (bpf_probe_read_kernel(&name, sizeof(name), &s_mtd->name) == 0) {
            if (bpf_probe_read_kernel_str(tmp_name, sizeof(tmp_name), name) > 0) {
                put_ebpf_event_log(event, tmp_name, ebpf_strnlen(tmp_name, sizeof(tmp_name)), TYPE_STR);
            }
        }
    }

    lsm_events.ringbuf_submit(event, 0);
    return 0;
}


LSM_PROBE(sb_kern_mount, struct super_block *sb) {
    struct ebpf_event *event = lsm_events.ringbuf_reserve(sizeof(struct ebpf_event));
    if (event == NULL) {
        return -EACCES;
    }
    initialize_ebpf_event_log(event, "sb_kern_mount");

    char tmp_name[32];
    if (sb->s_root != NULL) {
        struct dentry *s_root = sb->s_root;
        struct qstr name;
        if (bpf_probe_read_kernel(&name, sizeof(name), &s_root->d_name) == 0) {
            if (bpf_probe_read_kernel_str(tmp_name, sizeof(tmp_name), name.name) > 0) {
                put_ebpf_event_log(event, tmp_name, ebpf_strnlen(tmp_name, sizeof(tmp_name)), TYPE_STR);
            }
        }
    }

    if (bpf_probe_read_kernel_str(tmp_name, sizeof(tmp_name), sb->s_id) > 0) {
        put_ebpf_event_log(event, tmp_name, ebpf_strnlen(tmp_name, sizeof(tmp_name)), TYPE_STR);
    }

    if (sb->s_mtd != NULL) {
        struct mtd_info *s_mtd = sb->s_mtd;
        char *name = NULL;
        if (bpf_probe_read_kernel(&name, sizeof(name), &s_mtd->name) == 0) {
            if (bpf_probe_read_kernel_str(tmp_name, sizeof(tmp_name), name) > 0) {
                put_ebpf_event_log(event, tmp_name, ebpf_strnlen(tmp_name, sizeof(tmp_name)), TYPE_STR);
            }
        }
    }

    lsm_events.ringbuf_submit(event, 0);
    return 0;
}