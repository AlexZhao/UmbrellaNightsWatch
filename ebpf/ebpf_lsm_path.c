// SPDX-License-Identifier: 2023
// Copyright Alex Zhao
//  track symbol link violation 
//
#include <linux/fs.h>  
#include <linux/types.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/errno.h>
#include <linux/stat.h>

#include <linux/uidgid.h>

#include "ebpf/ebpf_exe.h"
#include "ebpf/ebpf_str.h"
#include "ebpf/ebpf_event.h"

BPF_RINGBUF_OUTPUT(lsm_events, 8);

// simple comm to identify task, it shall use task_struct with 
// executable file and credential
struct task_info {
    char comm[16];
};



/// @brief 
/// @param  
/// @param dir 
/// @param dentry 
LSM_PROBE(path_unlink, const struct path *dir, struct dentry *dentry) {
    return 0;
}



/// @brief 
/// @param  
/// @param dir 
/// @param dentry 
/// @param mode 
LSM_PROBE(path_mkdir, const struct path *dir, struct dentry *dentry,
	 umode_t mode) {

    return 0;
}




/// @brief 
/// @param  
/// @param dir 
/// @param dentry 
LSM_PROBE(path_rmdir, const struct path *dir, struct dentry *dentry) {
    return 0;
}




/// @brief 
/// @param  
/// @param dir 
/// @param dentry 
/// @param mode 
/// @param dev 
LSM_PROBE(path_mknod, const struct path *dir, struct dentry *dentry,
	 umode_t mode, unsigned int dev) {
    return 0;
}




/// @brief 
/// @param  
/// @param path 
LSM_PROBE(path_truncate, const struct path *path) {
    return 0;
}






/// @brief 
/// @param  
/// @param dir 
/// @param dentry 
/// @param old_name 
LSM_PROBE(path_symlink, const struct path *dir, struct dentry *dentry, const char *old_name) {
    return 0;
}



/// @brief 
/// @param  
/// @param old_dentry 
/// @param new_dir 
/// @param new_dentry 
LSM_PROBE(path_link, struct dentry *old_dentry, const struct path *new_dir, struct dentry *new_dentry) {
    return 0;
}


/// @brief 
/// @param  
/// @param old_dir 
/// @param old_dentry 
/// @param new_dir 
/// @param new_dentry 
/// @param flags 
LSM_PROBE(path_rename, const struct path *old_dir,
	 struct dentry *old_dentry, const struct path *new_dir,
	 struct dentry *new_dentry, unsigned int flags) {

    return 0;
}


/// @brief Check the file change mod to have 777, some file with Other read/write,
///        file with executable...
///#define S_ISUID  0004000
///#define S_ISGID  0002000
///#define S_ISVTX  0001000
///
///#define S_IRWXU 00700
///#define S_IRUSR 00400
///#define S_IWUSR 00200
///#define S_IXUSR 00100
///
///#define S_IRWXG 00070
///#define S_IRGRP 00040
///#define S_IWGRP 00020
///#define S_IXGRP 00010
///
///#define S_IRWXO 00007
///#define S_IROTH 00004
///#define S_IWOTH 00002
///#define S_IXOTH 00001
/// @param  
/// @param path 
/// @param mode 
LSM_PROBE(path_chmod, const struct path *path, umode_t mode) {    
    struct qstr name;
    if (bpf_probe_read_kernel(&name, sizeof(name), &(path->dentry->d_name)) != 0) {
        return -EACCES;
    }

    char filename[30];
    ebpf_memset(filename, 0, sizeof(filename));
    if (bpf_probe_read_kernel_str(filename, sizeof(filename), name.name) < 0) {
        return -EACCES;
    }
    filename[29] = 0;

    //bpf_trace_printk("chmod %s\n", filename);

    struct task_info app_name;
    ebpf_memset(app_name.comm, 0, sizeof(app_name.comm));
    if (ebpf_get_current_task_app_name(app_name.comm, sizeof(app_name.comm)) != 0) {
        return -EACCES;
    }

    char umode[4];
    ebpf_memset(umode, 0, sizeof(umode));
    char *ptr = umode;
    if (mode & S_IRUSR) {
        *ptr ++ = 'r';
    }

    if (mode & S_IWUSR) {
        *ptr ++ = 'w';
    }

    if (mode & S_IXUSR) {
        *ptr ++ = 'x';
    }

    char gmode[4];
    ebpf_memset(gmode, 0, sizeof(gmode));
    ptr = gmode;
    if (mode & S_IRGRP) {
        *ptr ++ = 'r';
    }

    if (mode & S_IWGRP) {
        *ptr ++ = 'w';
    }

    if (mode & S_IXGRP) {
        *ptr ++ = 'x';
    }

    char omode[4];
    ebpf_memset(omode, 0, sizeof(omode));
    ptr = omode;
    if (mode & S_IROTH) {
        *ptr ++ = 'r';
    }

    if (mode & S_IWOTH) {
        *ptr ++ = 'w'; 
    }

    if (mode & S_IXOTH) {
        *ptr ++ = 'x';
    }

    struct ebpf_event *event = lsm_events.ringbuf_reserve(sizeof(struct ebpf_event));
    if (event != NULL) {
        initialize_ebpf_event_log(event, "path_chmod");
        put_ebpf_event_log(event, (const char *)app_name.comm, ebpf_strnlen(app_name.comm, sizeof(app_name.comm)), TYPE_STR);
        put_ebpf_event_log(event, (const char *)filename, ebpf_strnlen(filename, sizeof(filename)), TYPE_STR);
        put_ebpf_event_log(event, (const char *)umode, ebpf_strnlen(umode, sizeof(umode)), TYPE_STR);
        put_ebpf_event_log(event, (const char *)gmode, ebpf_strnlen(gmode, sizeof(gmode)), TYPE_STR);
        put_ebpf_event_log(event, (const char *)omode, ebpf_strnlen(omode, sizeof(omode)), TYPE_STR);
        lsm_events.ringbuf_submit(event, 0);
    }

    return 0;
}



/// something hide in the BCC complier
/// wrong below
/// LSM_HOOK(int, 0, path_chown, const struct path *path, kuid_t uid, kgid_t gid)
/// TODO this is serious, it direct can passthrough the all Security Control builtin kernel
/// @brief 
/// @param  
/// @param path 
/// @param uid 
/// @param gid 
LSM_PROBE(path_chown, const struct path *path) {
    return 0;
}



/// @brief 
/// @param  
/// @param path 
LSM_PROBE(path_chroot, const struct path *path) {

    return 0;
}



/// @brief 
/// @param  
/// @param path 
/// @param mask 
/// @param obj_type 
LSM_PROBE(path_notify, const struct path *path, u64 mask,
	 unsigned int obj_type) {

    return 0;
}