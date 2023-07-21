// SPDX-License-Identifier: 2023
// Copyright Alex Zhao
// eBPF based struct *file access function
#ifndef EBPF_FILE
#define EBPF_FILE

#include <linux/fs.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/errno.h>

#include "ebpf/ebpf_str.h"

#define MAX_FILE_DIR_DEPTH 10
#define MAX_FILE_NAME_LEN 64

// basic structure used to track file
struct ebpf_file_path {
    char path[MAX_FILE_DIR_DEPTH][MAX_FILE_NAME_LEN];
    int depth;
};

BPF_PERCPU_ARRAY(cur_file_path_array, struct ebpf_file_path, 1);

/// @brief  track struct file * to ebpf_file_path struct  
/// @param file 
/// @param file_path 
/// @return 
static __always_inline int ebpf_get_file_path(struct file *file, struct ebpf_file_path *file_path) {
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

        if (bpf_probe_read_kernel_str(file_path->path[0], MAX_FILE_NAME_LEN, dname.name) < 0) {
            return -EACCES;
        }
        
        struct dentry *parent = NULL;
        if (bpf_probe_read_kernel(&parent, sizeof(parent), &track_path.dentry->d_parent) != 0) {
            return -EACCES;
        }

        int depth = 1;
        #pragma clang loop unroll(full)
        for (int i = 1; i < MAX_FILE_DIR_DEPTH; i++) {
            if (bpf_probe_read_kernel(&dname, sizeof(dname), &parent->d_name) != 0) {
                return -EACCES;
            }

            if (bpf_probe_read_kernel_str(file_path->path[depth], MAX_FILE_NAME_LEN, dname.name) < 0) {
                file_path->depth = depth;
                return -EACCES;
            }

            if (ebpf_strncmp(file_path->path[depth], "/", 2) == 0) {
                file_path->depth = depth;
                return 0;
            }

            if (bpf_probe_read_kernel(&parent, sizeof(parent), &parent->d_parent) != 0) {
                return -EACCES;
            }

            if (parent == NULL) {
                break;
            }

            depth ++;
        }
        file_path->depth = depth;
    } else {
        return -EACCES;
    }

    return 0;
}


static __always_inline int ebpf_get_file_name(struct file *file, char *filename, int len) {
    struct path track_path;
    struct qstr dname;

    if (bpf_probe_read_kernel(&track_path, sizeof(track_path), &file->f_path) != 0) {
        return -EACCES;
    }

    // Copy Small name of the exec file
    if (bpf_probe_read_kernel(&dname, sizeof(dname), &track_path.dentry->d_name) != 0) {
        return -EACCES;
    }

    if (bpf_probe_read_kernel_str(filename, len, dname.name) < 0) {
        return -EACCES;
    }

    return 0;
}

#endif