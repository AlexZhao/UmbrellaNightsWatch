// SPDX-License-Identifier: 2023
// Copyright Zhao Zhe (Alex)
//
// eBPF based Security Module
// Key
#include <linux/errno.h>
#include <linux/key.h>
#include <linux/cred.h>

#include "ebpf/ebpf_event.h"
#include "ebpf/ebpf_exe.h"

BPF_RINGBUF_OUTPUT(lsm_events, 2);

LSM_PROBE(key_alloc, struct key *key, const struct cred *cred,
	 unsigned long flags) {
    return -EPERM;
}

LSM_PROBE(key_permission, key_ref_t key_ref, const struct cred *cred,
	 enum key_need_perm need_perm) {

    return -EPERM;
}

LSM_PROBE(key_getsecurity, struct key *key, char **_buffer) {
    return -EPERM;
}

LSM_PROBE(watch_key, struct key *key) {
    return -EPERM;
}