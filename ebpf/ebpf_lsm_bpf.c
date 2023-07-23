// SPDX-License-Identifier: 2023
// Copyright Alex Zhao
//
// eBPF based Security Module
//  BPF syscall security check
// Mainly used to record all the behavior of BPF syscall except nw itself
// NW internal shield will block most of the access to BPF syscall
//
#include <linux/sched.h>
#include <linux/binfmts.h>
#include <linux/errno.h>
#include <linux/cred.h>
#include <linux/bpf.h>

#include "ebpf/ebpf_file.h"
#include "ebpf/ebpf_event.h"
#include "ebpf/ebpf_str.h"
#include "ebpf/ebpf_exe.h"


BPF_RINGBUF_OUTPUT(lsm_events, 8);

/// @brief 
/// @param  
/// @param cmd 
/// @param attr 
/// @param size 
LSM_PROBE(bpf, int cmd, union bpf_attr *attr, unsigned int size) {
    char bpf_syscall_op[32];
    ebpf_memset(bpf_syscall_op, 0, sizeof(bpf_syscall_op));

    switch (cmd) {
    case BPF_MAP_CREATE:
        ebpf_strncpy(bpf_syscall_op, "map_create", 11);
        break;
    case BPF_PROG_LOAD:
        ebpf_strncpy(bpf_syscall_op, "prog_load", 10);
        break;
    case BPF_PROG_ATTACH:
        ebpf_strncpy(bpf_syscall_op, "prog_attach", 12);
        break;
    case BPF_PROG_DETACH:
        ebpf_strncpy(bpf_syscall_op, "prog_detach", 12);
        break;
    case BPF_MAP_LOOKUP_ELEM:
        ebpf_strncpy(bpf_syscall_op, "map_lookup_elem", 16);
        break;
    case BPF_MAP_UPDATE_ELEM:
        ebpf_strncpy(bpf_syscall_op, "map_update_elem", 16);
        break;
    case BPF_MAP_DELETE_ELEM:
        ebpf_strncpy(bpf_syscall_op, "map_delete_elem", 16);
        break;
    case BPF_MAP_GET_NEXT_KEY:
        ebpf_strncpy(bpf_syscall_op, "map_get_next_key", 17);
        break;
    case BPF_OBJ_PIN:
        ebpf_strncpy(bpf_syscall_op, "obj_pin", 8);
        break;
    case BPF_OBJ_GET:
        ebpf_strncpy(bpf_syscall_op, "obj_get", 8);
        break;
    case BPF_MAP_LOOKUP_AND_DELETE_ELEM:
        ebpf_strncpy(bpf_syscall_op, "map_lookup_and_delete_elem", 27);
        break;
    case BPF_MAP_LOOKUP_BATCH:
        ebpf_strncpy(bpf_syscall_op, "map_lookup_batch", 17);
        break;
    case BPF_MAP_LOOKUP_AND_DELETE_BATCH:
        ebpf_strncpy(bpf_syscall_op, "map_lookup_and_delete_batch", 29);
        break;
    case BPF_MAP_UPDATE_BATCH:
        ebpf_strncpy(bpf_syscall_op, "map_update_batch", 17);
        break;
    case BPF_MAP_DELETE_BATCH:
        ebpf_strncpy(bpf_syscall_op, "map_delete_batch", 17);
        break;
    case BPF_LINK_CREATE:
        ebpf_strncpy(bpf_syscall_op, "link_create", 12);
        break;
    case BPF_LINK_UPDATE:
        ebpf_strncpy(bpf_syscall_op, "link_update", 12);
        break;
    case BPF_LINK_GET_FD_BY_ID:
        ebpf_strncpy(bpf_syscall_op, "link_get_fd_by_id", 18);
        break;
    case BPF_LINK_GET_NEXT_ID:
        ebpf_strncpy(bpf_syscall_op, "link_get_next_id", 17);
        break;
    case BPF_ENABLE_STATS:
        ebpf_strncpy(bpf_syscall_op, "enable_stats", 13);
        break;
    case BPF_ITER_CREATE:
        ebpf_strncpy(bpf_syscall_op, "iter_create", 12);
        break;
    case BPF_LINK_DETACH:
        ebpf_strncpy(bpf_syscall_op, "link_detach", 12);
        break;
    case BPF_PROG_BIND_MAP:
        ebpf_strncpy(bpf_syscall_op, "prog_bind_map", 14);
        break;
    case BPF_PROG_RUN:
        ebpf_strncpy(bpf_syscall_op, "prog_run", 9);
        break;
    case BPF_PROG_GET_NEXT_ID:
        ebpf_strncpy(bpf_syscall_op, "prog_get_next_id", 17);
        break;
	case BPF_MAP_GET_NEXT_ID:
        ebpf_strncpy(bpf_syscall_op, "map_get_next_id", 16);
        break;
	case BPF_PROG_GET_FD_BY_ID:
        ebpf_strncpy(bpf_syscall_op, "prog_get_fd_by_id", 18);
        break;
	case BPF_MAP_GET_FD_BY_ID:
        ebpf_strncpy(bpf_syscall_op, "map_get_fd_by_id", 17);
        break;
	case BPF_OBJ_GET_INFO_BY_FD:
        ebpf_strncpy(bpf_syscall_op, "obj_get_info_by_id", 19);
        break;
	case BPF_PROG_QUERY:
        ebpf_strncpy(bpf_syscall_op, "prog_query", 11);
        break;
	case BPF_RAW_TRACEPOINT_OPEN:
        ebpf_strncpy(bpf_syscall_op, "raw_tracepoint_open", 20);
        break;
    case BPF_BTF_LOAD:
        ebpf_strncpy(bpf_syscall_op, "btf_load", 9);
        break;
	case BPF_BTF_GET_FD_BY_ID:
        ebpf_strncpy(bpf_syscall_op, "btf_get_fd_by_id", 17);
        break;
	case BPF_TASK_FD_QUERY:
        ebpf_strncpy(bpf_syscall_op, "task_fd_query", 14);
        break;
    case BPF_MAP_FREEZE:
        ebpf_strncpy(bpf_syscall_op, "map_freeze", 11);
        break;
	case BPF_BTF_GET_NEXT_ID:
        ebpf_strncpy(bpf_syscall_op, "btf_get_next_id", 16);
        break;
    default:
        ebpf_strncpy(bpf_syscall_op, "unknown", 8);
        break;
    }

    char app_name[16];
    ebpf_memset(app_name, 0, sizeof(app_name));
    if (ebpf_get_current_task_app_name(app_name, sizeof(app_name)) == 0) {
        struct ebpf_event *event = lsm_events.ringbuf_reserve(sizeof(struct ebpf_event));
        if (event != NULL) {
            initialize_ebpf_event_log(event, "bpf"); 
            put_ebpf_event_log(event, app_name, ebpf_strnlen(app_name, sizeof(app_name)), TYPE_STR);
            put_ebpf_event_log(event, bpf_syscall_op, ebpf_strnlen(bpf_syscall_op, sizeof(bpf_syscall_op)), TYPE_STR);           
            lsm_events.ringbuf_submit(event, 0);
        } else {
            return -EACCES;
        }
    } else {
        return -EACCES;
    }

    return 0;
}