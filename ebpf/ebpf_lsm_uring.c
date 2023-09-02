// SPDX-License-Identifier: 2023
// Copyright Zhao Zhe (Alex)
//
// eBPF based Security Module for IO URING
// 
#include <linux/errno.h>
#include <linux/cred.h>
#include <linux/io_uring.h>

#include "ebpf/ebpf_event.h"

BPF_RINGBUF_OUTPUT(lsm_events, 4);

LSM_PROBE(uring_override_creds, const struct cred *new) {
    return -EPERM;
}

LSM_PROBE(uring_sqpoll) {
    return -EPERM;
}

LSM_PROBE(uring_cmd, struct io_uring_cmd *ioucmd) {
    return -EPERM;
}
