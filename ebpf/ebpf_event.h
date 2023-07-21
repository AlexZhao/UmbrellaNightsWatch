// SPDX-License-Identifier: 2023
// Copyright Alex Zhao
// eBPF event unified log for all MACs events
//
#ifndef EBPF_EVENT
#define EBPF_EVENT

#include <linux/errno.h>
#include "ebpf/ebpf_str.h"

#define MAXIMUM_EBPF_EVENT_SECTION_LEN 32
#define MAXIMUM_EBPF_EVENT_SECTION 6

#define TYPE_STR 0
#define TYPE_I16 1
#define TYPE_U16 2
#define TYPE_I32 3
#define TYPE_U32 4
#define TYPE_I64 5
#define TYPE_U64 6
#define TYPE_IPV4 7
#define TYPE_IPV6 8

// TODO TLV 
// A verifier bug existed with the boundary check
// the sections[] configured with maximum + 1
typedef struct ebpf_event {
    int ebpf_event_section;
    unsigned long long timestamp;
    char lsm_func[MAXIMUM_EBPF_EVENT_SECTION_LEN];
    char sections[MAXIMUM_EBPF_EVENT_SECTION + 1][MAXIMUM_EBPF_EVENT_SECTION_LEN];
} ebpf_event;

static __always_inline void initialize_ebpf_event_log(ebpf_event *event, const char* lsm_func) {
    event->ebpf_event_section = 0;
    ebpf_strncpy(event->lsm_func, lsm_func, sizeof(event->lsm_func));
    event->timestamp = bpf_ktime_get_tai_ns();
}

static __always_inline int get_ebpf_event_current_section(ebpf_event *event) {
    return event->ebpf_event_section;
}

static __always_inline int set_ebpf_event_current_section(ebpf_event *event, unsigned int section) {
    int index = event->ebpf_event_section;

    if (section - index == 1) {
        event->ebpf_event_section = section;
        return 0;
    }

    return -1;
}

static int put_ebpf_event_log(ebpf_event *event, const char *log, const unsigned char len, const unsigned char type_of_log) {
    int index = event->ebpf_event_section;

    // if the section boudary not have +1, this need to be maximum - 1
    // the boundary check will fail
    if (index < MAXIMUM_EBPF_EVENT_SECTION && index >= 0) {
        event->sections[index][0] = type_of_log;
        event->sections[index][1] = len;

        if (len > MAXIMUM_EBPF_EVENT_SECTION_LEN - 2) {
            return -E2BIG;
        }

        if (type_of_log == TYPE_STR) {
            ebpf_strncpy(&event->sections[index][2], log, len);
        } else {
            ebpf_memncpy(&event->sections[index][2], log, MAXIMUM_EBPF_EVENT_SECTION_LEN - 2, len);
        }

        event->ebpf_event_section = event->ebpf_event_section + 1;
    }

    return event->ebpf_event_section;
}
#endif