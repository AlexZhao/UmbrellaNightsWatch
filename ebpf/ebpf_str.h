// SPDX-License-Identifier: 2023
// Copyright Alex Zhao
//
// eBPF string operation
//
#ifndef EBPF_STR
#define EBPF_STR

#define EBPF_MEMSET_THRESHOLD 32
#define EBPF_STR_MAXIMUM_LEN 256

static int ebpf_strncpy(char *tgt, const char *src, int len) {
    if (len > EBPF_STR_MAXIMUM_LEN) {
        return -1;
    }

    for (int i = 0; i < len - 1; i++) {
        *(tgt + i) = *(src + i);

        if (*(tgt + i) == 0) {
            return i + 1;
        }
    }

    *(tgt + len - 1) = 0;

    return len;
}

/// @brief  Check target str start with prefix string
/// @param str 
/// @param startwith 
/// @param len 
/// @param start_len 
/// @return 
static int ebpf_strnstartwith(const char *str, const char *startwith, int len, int start_len) {
    if (len > EBPF_STR_MAXIMUM_LEN) {
        return -1;
    }

    if (start_len > len) {
        return -1;
    }

    for (int i = 0; i < len - 1; i++) {
        if (*(startwith + i) == 0) {
            return 0;
        }
        
        if (*(str + i) != *(startwith + i)) {
            return -1;
        }
    }

    return -1;
}

static void ebpf_memset(char *target, char data, int len) {
    if (len > EBPF_STR_MAXIMUM_LEN) {
        return;
    }

    #pragma clang loop unroll(full)
    for (int i = 0; i < len; i ++) {
        *(target + i) = data;
    }
}

static int ebpf_memncpy(char *target, const char *src, int len, int src_len) {
    if (len < src_len) {
        return -1;
    }

    for (int i = 0; i < src_len; i++) {
        *(target + i) = *(src + i);
    }

    return src_len;
}

static int ebpf_strncmp(char *target, char *src, int len) {
    if (len > EBPF_STR_MAXIMUM_LEN) {
        return -1;
    }

    #pragma clang loop unroll(full)
    for (int i = 0; i < len; i++) {
        if (*(target + i) != *(src + i)) {
            return i + 1;
        }

        if (*(target + i) == 0) {
            return 0;
        }
    }

    return -1;
}

static int ebpf_strnlen(const char *src, int len) {
    if (len > EBPF_STR_MAXIMUM_LEN) {
        return -1;
    }

    for (int i = 0; i < len; i ++) {
        if (*(src + i) == 0) {
            return i + 1;
        }
    }

    return -1;
}

/// @brief ebpf_strncat only can work with < 2 length of copy
/// @param target 
/// @param src 
/// @param len 
/// @param src_len 
/// @return 
static int ebpf_strncat(char *target, const char *src, int len, int src_len) {
    int start = -1;
    int copy_len = -1;

    if (len > EBPF_STR_MAXIMUM_LEN) {
        return -1;
    }

    start = ebpf_strnlen(target, len) - 1;
    if (start < 0) {
        return -1;
    }

    copy_len = len - start;
    if (copy_len <= 0) {
        return -1;
    }
    
    if (copy_len > src_len) {
        copy_len = src_len;
    }

    int tgt_str_len = ebpf_strncpy(target + start, src, copy_len);
    
    return start + tgt_str_len;
}

static void ebpf_dumphex(char *target, int len) {
    if (len > EBPF_STR_MAXIMUM_LEN) {
        return;
    }

    #pragma clang loop unroll(full)
    for (int i = 0; i < len; i ++) {

    }
}

#endif