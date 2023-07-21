// SPDX-License-Identifier: 2023
// Copyright Alex Zhao
//
#ifndef EBPF_EXE
#define EBPF_EXE

#include <linux/errno.h>
#include <linux/dcache.h>
#include <linux/fs.h>

#include "ebpf/ebpf_str.h"

#define MAXIMUM_EXE_FILE_NAME 4096
#define MAXIMUM_EXE_SMALL_FILE_NAME 128
#define MAXIMUM_FOLDER_DEPTH 10

struct exec_file_name {
    struct dentry entry;
    char small_name[MAXIMUM_EXE_SMALL_FILE_NAME];
    char file_name[MAXIMUM_EXE_FILE_NAME];
};

BPF_PERCPU_ARRAY(cur_exe_file_name_array, struct exec_file_name, 1);

static __always_inline int ebpf_get_task_exec_file(struct task_struct *task, struct exec_file_name *exe_file_name) {
    struct file *exe_file = NULL;
	struct mm_struct *mm = NULL;
    struct path exe_path;
    struct qstr dname;
    
    if (exe_file_name == NULL) {
        return -EACCES;
    } 

    if (bpf_probe_read_kernel(&mm, sizeof(mm), &task->mm) != 0) {
        return -EACCES;
    }

    if (bpf_probe_read_kernel(&exe_file, sizeof(exe_file), &mm->exe_file) != 0) {
        return -EACCES;
    }

    if (exe_file) {
        if (bpf_probe_read_kernel(&exe_path, sizeof(exe_path), &exe_file->f_path) != 0) {
            return -EACCES;
        }

        // Copy Small name of the exec file
        if (bpf_probe_read_kernel_str(exe_file_name->small_name, MAXIMUM_EXE_SMALL_FILE_NAME, exe_path.dentry->d_iname) < 0) {
            return -EACCES;
        }

        // Copy qstr name of the exec file
        // Copy Small name of the exec file
        if (bpf_probe_read_kernel(&dname, sizeof(dname), &exe_path.dentry->d_name) != 0) {
            return -EACCES;
        }

        if (bpf_probe_read_kernel_str(exe_file_name->file_name, MAXIMUM_EXE_FILE_NAME, dname.name) < 0) {
            return -EACCES;
        }
    }

    return 0;
}


static __always_inline int ebpf_get_task_app_name(struct task_struct *task, char *app_name, int len) {
    struct file *exe_file = NULL;
    struct mm_struct *mm = NULL;
    struct path exe_path;
    struct qstr dname;

    if (task == NULL) {
        return -EACCES;
    }

    if (bpf_probe_read_kernel(&mm, sizeof(mm), &task->mm) != 0) {
        return -EACCES;
    }

    if (bpf_probe_read_kernel(&exe_file, sizeof(exe_file), &mm->exe_file) != 0) {
        return -EACCES;
    }

    if (exe_file) {
        if (bpf_probe_read_kernel(&exe_path, sizeof(exe_path), &exe_file->f_path) != 0) {
            return -EACCES;
        }

        // Copy Small name of the exec file
        if (bpf_probe_read_kernel(&dname, sizeof(dname), &exe_path.dentry->d_name) != 0) {
            return -EACCES;
        }

        if (bpf_probe_read_kernel_str(app_name, len, dname.name) < 0) {
            return -EACCES;
        }

    } else {
        return -EACCES;
    }

    return 0;
}

static __always_inline int ebpf_get_current_task_app_name(char *app_name, int len) {
    struct task_struct *cur_task = (struct task_struct *)bpf_get_current_task();

    return ebpf_get_task_app_name(cur_task, app_name, len);
}

struct exec_file_path {
    char app_name[MAXIMUM_EXE_SMALL_FILE_NAME];
    char path[MAXIMUM_FOLDER_DEPTH][MAXIMUM_EXE_SMALL_FILE_NAME];
    int depth;
};

BPF_PERCPU_ARRAY(cur_exe_file_path_array, struct exec_file_path, 1);

/// @brief 
///    struct exec_file_path *cur_exec_file_path = NULL;
///    int key = 0;
///    cur_exec_file_path = cur_exe_file_path_array.lookup(&key);
///    if (cur_exec_file_path == NULL) {
///        return -EACCES;
///    }
///
///    if (ebpf_get_current_task_app_path(cur_exec_file_path) != 0) {
///        return -EACCES;
///    }
///
/// @param exe_file_path 
/// @return 
static __always_inline int ebpf_get_current_task_app_path(struct exec_file_path *exe_file_path) {
    struct task_struct *cur_task = (struct task_struct *)bpf_get_current_task();
    struct file *exe_file = NULL;
    struct mm_struct *mm = NULL;
    struct path exe_path;
    struct qstr dname;

    if (cur_task == NULL) {
        return -EACCES;
    }

    if (bpf_probe_read_kernel(&mm, sizeof(mm), &cur_task->mm) != 0) {
        return -EACCES;
    }

    if (bpf_probe_read_kernel(&exe_file, sizeof(exe_file), &mm->exe_file) != 0) {
        return -EACCES;
    }

    if (exe_file) {
        if (bpf_probe_read_kernel(&exe_path, sizeof(exe_path), &exe_file->f_path) != 0) {
            return -EACCES;
        }

        // Copy Small name of the exec file
        if (bpf_probe_read_kernel(&dname, sizeof(dname), &exe_path.dentry->d_name) != 0) {
            return -EACCES;
        }

        if (bpf_probe_read_kernel_str(exe_file_path->app_name, MAXIMUM_EXE_SMALL_FILE_NAME, dname.name) < 0) {
            return -EACCES;
        }
        
        struct dentry *parent = NULL;
        if (bpf_probe_read_kernel(&parent, sizeof(parent), &exe_path.dentry->d_parent) != 0) {
            return -EACCES;
        }

        int depth = 0;
        #pragma clang loop unroll(full)
        for (int i = 0; i < MAXIMUM_FOLDER_DEPTH; i++) {
            if (bpf_probe_read_kernel(&dname, sizeof(dname), &parent->d_name) != 0) {
                return -EACCES;
            }

            if (bpf_probe_read_kernel_str(exe_file_path->path[depth], MAXIMUM_EXE_SMALL_FILE_NAME, dname.name) < 0) {
                exe_file_path->depth = depth;
                return -EACCES;
            }

            if (ebpf_strncmp(exe_file_path->path[depth], "/", 2) == 0) {
                exe_file_path->depth = depth;
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
        exe_file_path->depth = depth;
    } else {
        return -EACCES;
    }

    return 0;
}

#define MAXIMUM_FOLDER_NAME_LEN 128

static int ebpf_concat_path(struct exec_file_path *cur_exec_file_path, char *path, int len) {
    if (cur_exec_file_path == NULL) {
        return -EACCES;
    }

    if (cur_exec_file_path->depth > MAXIMUM_FOLDER_DEPTH) {
        return -EACCES;
    }

//    for (int i = cur_exec_file_path->depth - 1; i >= 0; i--) {       
//    }
    int depth = cur_exec_file_path->depth - 1;
    if (depth >= 0) {
        ebpf_strncat(path, "/", len, 2);
        ebpf_strncat(path, cur_exec_file_path->path[depth], len, sizeof(cur_exec_file_path->path[depth]));    
    }

    depth = depth - 1;
    if (depth >= 0) {
        ebpf_strncat(path, "/", len, 2);
        ebpf_strncat(path, cur_exec_file_path->path[depth], len, sizeof(cur_exec_file_path->path[depth]));    
    }

    return 0;
}

/// @brief Recursive generate path
/// @param entry 
/// @return 
static int ebpf_get_path(struct dentry *entry, struct exec_file_path *cur_exec_file_path) {
    struct dentry *parent = NULL;
    struct qstr dname;
    
    if (entry == NULL) {
        return -EACCES;
    }
    parent = entry;

    if (cur_exec_file_path == NULL) {
        return -EACCES;
    }
    cur_exec_file_path->depth = 0;
    
    int depth = 0;
    for (int i = 0; i < MAXIMUM_FOLDER_DEPTH; i++) {
        if (bpf_probe_read_kernel(&dname, sizeof(dname), &parent->d_name) != 0) {
            return -EACCES;
        }

        if (bpf_probe_read_kernel_str(cur_exec_file_path->path[i], MAXIMUM_EXE_SMALL_FILE_NAME, dname.name) < 0) {
            return -EACCES;
        }

        if (ebpf_strncmp(cur_exec_file_path->path[i], "/", 2) == 0) {
            // recursive trace to / 
            break;
        }
        
        if (bpf_probe_read_kernel(&parent, sizeof(parent), &parent->d_parent) != 0) {
            return -EACCES;
        }

        if (parent == NULL) {
            break;
        }

        depth++;
    }
    cur_exec_file_path->depth = depth;

    return 0;
}

#endif