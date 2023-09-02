// SPDX-License-Identifier: 2023
// Copyright Zhao Zhe (Alex)
//
// eBPF based Security Module
//  Time Control
//
#include <linux/errno.h>
#include <linux/time.h>
#include <linux/time64.h>

#include "ebpf/ebpf_event.h"
#include "ebpf/ebpf_exe.h"
#include "ebpf/ebpf_str.h"

BPF_RINGBUF_OUTPUT(lsm_events, 2);



/// @brief bpf security hooks use security_settime
/// @param  
/// @param ts 
/// @param tz 
LSM_PROBE(settime, const struct timespec64 *ts, const struct timezone *tz) {
    struct ebpf_event *event = lsm_events.ringbuf_reserve(sizeof(struct ebpf_event));
    if (event == NULL) {
        return -EACCES;
    }
    initialize_ebpf_event_log(event, "settime");
    
    char app_name[32];
    if (ebpf_get_current_task_app_name(app_name, sizeof(app_name)) != 0) {
        lsm_events.ringbuf_discard(event, 0);
        return -EACCES;
    }
    put_ebpf_event_log(event, app_name, sizeof(app_name), TYPE_STR);
    lsm_events.ringbuf_submit(event, 0);
    return 0;
}
