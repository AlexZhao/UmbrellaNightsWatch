// SPDX-License-Identifier: 2022
// Copyright Zhao Zhe (Alex)
//
// File Access log, the real access after namei 
//
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/fdtable.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/dcache.h>

#include "ebpf/ebpf_exe.h"
#include "ebpf/ebpf_str.h"

BPF_RINGBUF_OUTPUT(prb_logs, 32);

#define MAX_FILENAME_LEN 128
#define MAX_COMMNAME_LEN 64
// currently allow to record 20 nested folder
#define MAX_FOLDER_DEPTH 20

#define FILE_OP_OPEN 1
#define FILE_OP_IOCTL 2

struct event {
    char comm[MAX_COMMNAME_LEN];
    int pid;
    int file_op;
    char path[MAX_FOLDER_DEPTH][MAX_FILENAME_LEN];
    int depth;
};



/// @brief ebpf_get_file_path full name path of a file
/// @param file 
/// @param event 
/// @return 0 success
///         1 exceed maximum depth of folder
///        <0 error
static __always_inline int ebpf_get_file_path(struct file *file, struct event *event) {
    struct path track_path;
    struct qstr dname;

    if (file) {
        if (bpf_probe_read_kernel(&track_path, sizeof(track_path), &file->f_path) != 0) {
            return -EACCES;
        }

        // Copy Small name of the exec file
        if (bpf_probe_read_kernel(&dname, sizeof(dname), &track_path.dentry->d_name) != 0) {
            return -EACCES;
        }

        if (bpf_probe_read_kernel_str(event->path[0], MAX_FILENAME_LEN, dname.name) < 0) {
            return -EACCES;
        }
        
        struct dentry *parent = NULL;
        if (bpf_probe_read_kernel(&parent, sizeof(parent), &track_path.dentry->d_parent) != 0) {
            return -EACCES;
        }

        int depth = 1;
        for (int i = 1; i < MAX_FOLDER_DEPTH; i++) {
            if (bpf_probe_read_kernel(&dname, sizeof(dname), &parent->d_name) != 0) {
                break;
            }

            if (bpf_probe_read_kernel_str(event->path[depth], MAX_FILENAME_LEN, dname.name) < 0) {
                break;
            }

            if (ebpf_strncmp(event->path[depth], "/", 2) == 0) {
                event->depth = depth - 1;
                return 0;
            }

            if (bpf_probe_read_kernel(&parent, sizeof(parent), &parent->d_parent) != 0) {
                break;
            }

            if (parent == NULL) {
                break;
            }
            depth ++;
        }
        event->depth = depth;
        return 1;
    } else {
        return -EACCES;
    }

    return 0;
}




/// @brief  LSM based access tracking, no bypass 
/// @param  
/// @param file 
LSM_PROBE(file_open, struct file *file) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) {
        return 0;
    }
    
    struct event *event = ring_file_log.ringbuf_reserve(sizeof(struct event));
    if (!event) {
        return 0;
    }

    if (ebpf_get_task_app_name(task, event->comm, sizeof(event->comm)) != 0) {
        ring_file_log.ringbuf_discard(event, 0);
        return 0;
    }
 
    bpf_probe_read_kernel(&event->pid, sizeof(event->pid), &task->pid);
    event->depth = 0;
    if (ebpf_get_file_path(file, event) < 0) {
        ring_file_log.ringbuf_discard(event, 0);
        return 0;
    }
    event->file_op = FILE_OP_OPEN;
    ring_file_log.ringbuf_submit(event, 0);

    return 0;
}


