// SPDX-License-Identifier: 2023
// Copyright Alex Zhao
//  eBPF Configuration log for all probes
#ifndef EBPF_LOG
#define EBPF_LOG

#include <linux/errno.h>
#include "ebpf/ebpf_str.h"

#define MAXIMUM_EBPF_LOG_LEN 6
#define MAXIMUM_EBPF_LOG_SECTION_LEN 32

typedef struct ebpf_prb_log {
    unsigned int ebpf_log_section;
    unsigned long long timestamp;
    char func[MAXIMUM_EBPF_LOG_SECTION_LEN];
    char sections[MAXIMUM_EBPF_LOG_LEN][MAXIMUM_EBPF_LOG_SECTION_LEN];
} ebpf_prb_log;

#define TYPE_STR 0
#define TYPE_I32 1
#define TYPE_U32 2
#define TYPE_I64 3
#define TYPE_U64 4
#define TYPE_SOCKADDR 5

/// @brief 
/// @param log 
/// @param func_name 
/// @return 
static __always_inline void initialize_ebpf_log(struct ebpf_prb_log *log, const char *func_name) {
    log->ebpf_log_section = 0;
    log->timestamp = bpf_ktime_get_tai_ns();
    ebpf_strncpy(log->func, func_name, sizeof(log->func));
}


/// @brief 
/// @param log 
/// @param log_str 
/// @param len 
/// @param type_of_log 
/// @return 
static __always_inline int put_ebpf_prb_log(struct ebpf_prb_log *log, const char *log_str, const unsigned char len, const unsigned char type_of_log) {
    unsigned int current_section = log->ebpf_log_section;

    if (current_section >= MAXIMUM_EBPF_LOG_LEN) {
        return -EACCES;
    }

    log->sections[current_section][0] = type_of_log;
    log->sections[current_section][1] = len;

    if (len > MAXIMUM_EBPF_LOG_SECTION_LEN - 2) {
        return -E2BIG;
    }

    if (type_of_log == TYPE_STR) {
        ebpf_strncpy(&log->sections[current_section][2], log_str, len);
    } else {
        ebpf_memncpy(&log->sections[current_section][2], log_str, MAXIMUM_EBPF_LOG_SECTION_LEN - 2, len);
    }
    log->ebpf_log_section ++;

    return 0;
}


#endif