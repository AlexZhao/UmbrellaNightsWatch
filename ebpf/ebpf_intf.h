// SPDX-License-Identifier: 2023
// Copyright Alex Zhao
//  eBPF Configuration interactive data struct with userspace daemon
#ifndef EBPF_INTF
#define EBPF_INTF

#define KMOD_NAME_LEN 64

struct kmod {
    char name[KMOD_NAME_LEN];
};


#endif