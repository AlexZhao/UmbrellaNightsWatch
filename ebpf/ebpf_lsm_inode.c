// SPDX-License-Identifier: 2023
// Copyright Alex Zhao
//  inode related security hook
//  VFS control
#include <linux/user_namespace.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/inode.h>
#include <linux/namei.h>

#include "ebpf/ebpf_event.h"
#include "ebpf/ebpf_exe.h"
#include "ebpf/ebpf_str.h"

BPF_RINGBUF_OUTPUT(lsm_events, 8);

// simple comm to identify task, it shall use task_struct with 
// executable file and credential
struct task_info {
    char comm[16];
};

/// @brief 
/// @param  
/// @param inode 
LSM_PROBE(inode_alloc_security, struct inode *inode) {
    return 0;
}


LSM_PROBE(inode_init_security, struct inode *inode,
	 struct inode *dir, const struct qstr *qstr, const char **name,
	 void **value, size_t *len) {

    return 0;
}



LSM_PROBE(inode_init_security_anon, struct inode *inode,
	 const struct qstr *name, const struct inode *context_inode) {

    return 0;
}




LSM_PROBE(inode_create, struct inode *dir, struct dentry *dentry,
	 umode_t mode) {
    
    struct task_info app_name;
    ebpf_memset(app_name.comm, 0, sizeof(app_name.comm));
    if (ebpf_get_current_task_app_name(app_name.comm, sizeof(app_name.comm)) != 0) {
        return -EACCES;
    }

    struct ebpf_event *event = lsm_events.ringbuf_reserve(sizeof(struct ebpf_event));
    if (event != NULL) {
        initialize_ebpf_event_log(event, "inode_create");
        put_ebpf_event_log(event, app_name.comm, ebpf_strnlen(app_name.comm, sizeof(app_name.comm)), TYPE_STR);
        lsm_events.ringbuf_submit(event, 0);
    }

    return 0;
}




LSM_PROBE(inode_link, struct dentry *old_dentry, struct inode *dir,
	 struct dentry *new_dentry) {

    return 0;
}



LSM_PROBE(inode_unlink, struct inode *dir, struct dentry *dentry) {
    return 0;
}



LSM_PROBE(inode_symlink, struct inode *dir, struct dentry *dentry,
	 const char *old_name) {

    return 0;
}



LSM_PROBE(inode_mkdir, struct inode *dir, struct dentry *dentry,
	 umode_t mode) {    
    struct task_info app_name;
    ebpf_memset(app_name.comm, 0, sizeof(app_name.comm));
    if (ebpf_get_current_task_app_name(app_name.comm, sizeof(app_name.comm)) != 0) {
        return -EACCES;
    }

    struct ebpf_event *event = lsm_events.ringbuf_reserve(sizeof(struct ebpf_event));
    if (event != NULL) {
        initialize_ebpf_event_log(event, "inode_mkdir");
        put_ebpf_event_log(event, app_name.comm, ebpf_strnlen(app_name.comm, sizeof(app_name.comm)), TYPE_STR);
        lsm_events.ringbuf_submit(event, 0);
    }

    return 0;
}



LSM_PROBE(inode_rmdir, struct inode *dir, struct dentry *dentry) {
    struct task_info app_name;
    ebpf_memset(app_name.comm, 0, sizeof(app_name.comm));
    if (ebpf_get_current_task_app_name(app_name.comm, sizeof(app_name.comm)) != 0) {
        return -EACCES;
    }

    struct ebpf_event *event = lsm_events.ringbuf_reserve(sizeof(struct ebpf_event));
    if (event != NULL) {
        initialize_ebpf_event_log(event, "inode_rmdir");
        put_ebpf_event_log(event, app_name.comm, ebpf_strnlen(app_name.comm, sizeof(app_name.comm)), TYPE_STR);
        lsm_events.ringbuf_submit(event, 0);
    }

    return 0;
}


LSM_PROBE(inode_mknod, struct inode *dir, struct dentry *dentry,
	 umode_t mode, dev_t dev) {
    struct task_info app_name;
    ebpf_memset(app_name.comm, 0, sizeof(app_name.comm));
    if (ebpf_get_current_task_app_name(app_name.comm, sizeof(app_name.comm)) != 0) {
        return -EACCES;
    }

    struct ebpf_event *event = lsm_events.ringbuf_reserve(sizeof(struct ebpf_event));
    if (event != NULL) {
        initialize_ebpf_event_log(event, "inode_mknod");
        put_ebpf_event_log(event, app_name.comm, ebpf_strnlen(app_name.comm, sizeof(app_name.comm)), TYPE_STR);
        lsm_events.ringbuf_submit(event, 0);
    }

    return 0;
}



LSM_PROBE(inode_rename, struct inode *old_dir, struct dentry *old_dentry,
	 struct inode *new_dir, struct dentry *new_dentry) {

    return 0;
}



LSM_PROBE(inode_readlink, struct dentry *dentry) {
    struct task_info app_name;
    ebpf_memset(app_name.comm, 0, sizeof(app_name.comm));
    if (ebpf_get_current_task_app_name(app_name.comm, sizeof(app_name.comm)) != 0) {
        return -EACCES;
    }

    struct ebpf_event *event = lsm_events.ringbuf_reserve(sizeof(struct ebpf_event));
    if (event != NULL) {
        initialize_ebpf_event_log(event, "inode_readlink");
        put_ebpf_event_log(event, app_name.comm, ebpf_strnlen(app_name.comm, sizeof(app_name.comm)), TYPE_STR);
        lsm_events.ringbuf_submit(event, 0);
    }

    return 0;
}



LSM_PROBE(inode_follow_link, struct dentry *dentry, struct inode *inode,
	 bool rcu) {
    struct task_info app_name;
    ebpf_memset(app_name.comm, 0, sizeof(app_name.comm));
    if (ebpf_get_current_task_app_name(app_name.comm, sizeof(app_name.comm)) != 0) {
        return -EACCES;
    }

    struct ebpf_event *event = lsm_events.ringbuf_reserve(sizeof(struct ebpf_event));
    if (event != NULL) {
        initialize_ebpf_event_log(event, "inode_follow_link");
        put_ebpf_event_log(event, app_name.comm, ebpf_strnlen(app_name.comm, sizeof(app_name.comm)), TYPE_STR);
        lsm_events.ringbuf_submit(event, 0);
    }

    return 0;
}



LSM_PROBE(inode_permission, struct inode *inode, int mask) {
    return 0;
}

/// @brief 
/// @param  
/// @param mnt_userns 
/// @param dentry 
/// @param attr 
LSM_PROBE(inode_setattr, struct user_namespace *mnt_userns, struct dentry *dentry, struct iattr *attr) {
    struct task_info app_name;
    ebpf_memset(app_name.comm, 0, sizeof(app_name.comm));
    if (ebpf_get_current_task_app_name(app_name.comm, sizeof(app_name.comm)) != 0) {
        return -EACCES;
    }

    struct ebpf_event *event = lsm_events.ringbuf_reserve(sizeof(struct ebpf_event));
    if (event != NULL) {
        initialize_ebpf_event_log(event, "inode_setattr");
        put_ebpf_event_log(event, app_name.comm, ebpf_strnlen(app_name.comm, sizeof(app_name.comm)), TYPE_STR);
        lsm_events.ringbuf_submit(event, 0);
    }

    return 0;
}


LSM_PROBE(inode_getattr, const struct path *path) {
    return 0;
}


LSM_PROBE(inode_setxattr, struct mnt_idmap *idmap,
	 struct dentry *dentry, const char *name, const void *value,
	 size_t size, int flags) {
    
    struct task_info app_name;
    ebpf_memset(app_name.comm, 0, sizeof(app_name.comm));
    if (ebpf_get_current_task_app_name(app_name.comm, sizeof(app_name.comm)) != 0) {
        return -EACCES;
    }

    struct ebpf_event *event = lsm_events.ringbuf_reserve(sizeof(struct ebpf_event));
    if (event != NULL) {
        initialize_ebpf_event_log(event, "inode_setxattr");
        put_ebpf_event_log(event, app_name.comm, ebpf_strnlen(app_name.comm, sizeof(app_name.comm)), TYPE_STR);
        lsm_events.ringbuf_submit(event, 0);
    }

    return 0;
}



LSM_PROBE(inode_getxattr, struct dentry *dentry, const char *name) {
    return 0;
}




LSM_PROBE(inode_listxattr, struct dentry *dentry) {
    return 0;
}



LSM_PROBE(inode_removexattr, struct mnt_idmap *idmap,
	 struct dentry *dentry, const char *name) {
    
    struct task_info app_name;
    ebpf_memset(app_name.comm, 0, sizeof(app_name.comm));
    if (ebpf_get_current_task_app_name(app_name.comm, sizeof(app_name.comm)) != 0) {
        return -EACCES;
    }

    struct ebpf_event *event = lsm_events.ringbuf_reserve(sizeof(struct ebpf_event));
    if (event != NULL) {
        initialize_ebpf_event_log(event, "inode_removexattr");
        put_ebpf_event_log(event, app_name.comm, ebpf_strnlen(app_name.comm, sizeof(app_name.comm)), TYPE_STR);
        lsm_events.ringbuf_submit(event, 0);
    }
    
    return 0;
}




LSM_PROBE(inode_set_acl, struct mnt_idmap *idmap,
	 struct dentry *dentry, const char *acl_name, struct posix_acl *kacl) {
    struct task_info app_name;
    ebpf_memset(app_name.comm, 0, sizeof(app_name.comm));
    if (ebpf_get_current_task_app_name(app_name.comm, sizeof(app_name.comm)) != 0) {
        return -EACCES;
    }

    struct ebpf_event *event = lsm_events.ringbuf_reserve(sizeof(struct ebpf_event));
    if (event != NULL) {
        initialize_ebpf_event_log(event, "inode_set_acl");
        put_ebpf_event_log(event, app_name.comm, ebpf_strnlen(app_name.comm, sizeof(app_name.comm)), TYPE_STR);
        lsm_events.ringbuf_submit(event, 0);
    }

    return 0;
}



LSM_PROBE(inode_get_acl, struct mnt_idmap *idmap,
	 struct dentry *dentry, const char *acl_name) {
    return 0;
}



LSM_PROBE(inode_remove_acl, struct mnt_idmap *idmap,
	 struct dentry *dentry, const char *acl_name) {
    struct task_info app_name;
    ebpf_memset(app_name.comm, 0, sizeof(app_name.comm));
    if (ebpf_get_current_task_app_name(app_name.comm, sizeof(app_name.comm)) != 0) {
        return -EACCES;
    }

    struct ebpf_event *event = lsm_events.ringbuf_reserve(sizeof(struct ebpf_event));
    if (event != NULL) {
        initialize_ebpf_event_log(event, "inode_remove_acl");
        put_ebpf_event_log(event, app_name.comm, ebpf_strnlen(app_name.comm, sizeof(app_name.comm)), TYPE_STR);
        lsm_events.ringbuf_submit(event, 0);
    }

    return 0;
}



LSM_PROBE(inode_need_killpriv, struct dentry *dentry) {
    struct task_info app_name;
    ebpf_memset(app_name.comm, 0, sizeof(app_name.comm));
    if (ebpf_get_current_task_app_name(app_name.comm, sizeof(app_name.comm)) != 0) {
        return -EACCES;
    }

    struct ebpf_event *event = lsm_events.ringbuf_reserve(sizeof(struct ebpf_event));
    if (event != NULL) {
        initialize_ebpf_event_log(event, "inode_need_killpriv");
        put_ebpf_event_log(event, app_name.comm, ebpf_strnlen(app_name.comm, sizeof(app_name.comm)), TYPE_STR);
        lsm_events.ringbuf_submit(event, 0);
    }

    return 0;
}



LSM_PROBE(inode_killpriv, struct mnt_idmap *idmap,
	 struct dentry *dentry) {

    struct task_info app_name;
    ebpf_memset(app_name.comm, 0, sizeof(app_name.comm));
    if (ebpf_get_current_task_app_name(app_name.comm, sizeof(app_name.comm)) != 0) {
        return -EACCES;
    }

    struct ebpf_event *event = lsm_events.ringbuf_reserve(sizeof(struct ebpf_event));
    if (event != NULL) {
        initialize_ebpf_event_log(event, "inode_killpriv");
        put_ebpf_event_log(event, app_name.comm, ebpf_strnlen(app_name.comm, sizeof(app_name.comm)), TYPE_STR);
        lsm_events.ringbuf_submit(event, 0);
    }

    return 0;
}



LSM_PROBE(inode_getsecurity, struct mnt_idmap *idmap,
	 struct inode *inode, const char *name, void **buffer, bool alloc) {
    return 0;
}



LSM_PROBE(inode_setsecurity, struct inode *inode,
	 const char *name, const void *value, size_t size, int flags) {
    
    struct task_info app_name;
    ebpf_memset(app_name.comm, 0, sizeof(app_name.comm));
    if (ebpf_get_current_task_app_name(app_name.comm, sizeof(app_name.comm)) != 0) {
        return -EACCES;
    }

    struct ebpf_event *event = lsm_events.ringbuf_reserve(sizeof(struct ebpf_event));
    if (event != NULL) {
        initialize_ebpf_event_log(event, "inode_setsecurity");
        put_ebpf_event_log(event, app_name.comm, ebpf_strnlen(app_name.comm, sizeof(app_name.comm)), TYPE_STR);
        lsm_events.ringbuf_submit(event, 0);
    }
    
    return 0;
}



LSM_PROBE(inode_listsecurity, struct inode *inode, char *buffer,
	 size_t buffer_size) {

    return 0;
}



LSM_PROBE(inode_copy_up, struct dentry *src, struct cred **new) {
    
    struct task_info app_name;
    ebpf_memset(app_name.comm, 0, sizeof(app_name.comm));
    if (ebpf_get_current_task_app_name(app_name.comm, sizeof(app_name.comm)) != 0) {
        return -EACCES;
    }

    struct ebpf_event *event = lsm_events.ringbuf_reserve(sizeof(struct ebpf_event));
    if (event != NULL) {
        initialize_ebpf_event_log(event, "inode_copy_up");
        put_ebpf_event_log(event, app_name.comm, ebpf_strnlen(app_name.comm, sizeof(app_name.comm)), TYPE_STR);
        lsm_events.ringbuf_submit(event, 0);
    }

    return 0;
}




LSM_PROBE(inode_copy_up_xattr, const char *name) {
    struct task_info app_name;
    ebpf_memset(app_name.comm, 0, sizeof(app_name.comm));
    if (ebpf_get_current_task_app_name(app_name.comm, sizeof(app_name.comm)) != 0) {
        return -EACCES;
    }

    struct ebpf_event *event = lsm_events.ringbuf_reserve(sizeof(struct ebpf_event));
    if (event != NULL) {
        initialize_ebpf_event_log(event, "inode_copy_up_xattr");
        put_ebpf_event_log(event, app_name.comm, ebpf_strnlen(app_name.comm, sizeof(app_name.comm)), TYPE_STR);
        lsm_events.ringbuf_submit(event, 0);
    }

    return 0;
}



