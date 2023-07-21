// SPDX-License-Identifier: 2023
// Copyright Alex Zhao
//
// eBPF based Security Module
//  Core functions of runtime mon
//  dynamic configurable MAC balance security/easy to use
//  no configuration required, all dynamic analysis offload to
//  Prophet
//
// New type of LSM without pre-configured LSM rules, but processing
// based on dynamic information gathered from computer system
//
#include <linux/sched.h>
#include <linux/socket.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/mm_types.h>
#include <linux/dcache.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/errno.h>
#include <linux/net.h>

#include <net/sock.h>
#include <net/af_unix.h>
#include <net/tcp_states.h>

#include "ebpf/ebpf_event.h"
#include "ebpf/ebpf_str.h"
#include "ebpf/ebpf_exe.h"

#if 0
#define DEBUG 1
#endif

BPF_RINGBUF_OUTPUT(lsm_events, 8);

#define MAXIMUM_LEN_OF_IPV4_BLOCK_LIST 1024
#define MAXIMUM_LEN_OF_IPV6_BLOCK_LIST 1024
#define MAXIMUM_LEN_OF_APP_ACCESS_LIST 1024

// simple comm to identify task, it shall use task_struct with 
// executable file and credential
struct task_info {
    char comm[16];
};

struct key_v4 {
    unsigned int prefixlen;
    unsigned int data;
};

BPF_LPM_TRIE(host_ipv4_allow_list, struct key_v4, int);

BPF_LPM_TRIE(ipv4_allow_list, struct key_v4, int);
BPF_LPM_TRIE(ipv4_allow_list_internal, struct key_v4, int);
BPF_LPM_TRIE(ipv4_allow_list_trusted_external, struct key_v4, int);

// Below can be used to configure per customized access control list associate with applcation
BPF_LPM_TRIE(ipv4_allow_list_s1, struct key_v4, int);
BPF_LPM_TRIE(ipv4_allow_list_s2, struct key_v4, int);
BPF_LPM_TRIE(ipv4_allow_list_s3, struct key_v4, int);
BPF_LPM_TRIE(ipv4_allow_list_s4, struct key_v4, int);
BPF_LPM_TRIE(ipv4_allow_list_s5, struct key_v4, int);

struct key_v6 {
    unsigned int prefixlen;
    unsigned int data[4];
};

BPF_LPM_TRIE(host_ipv6_allow_list, struct key_v6, int);

BPF_LPM_TRIE(ipv6_allow_list, struct key_v6, int);
BPF_LPM_TRIE(ipv6_allow_list_internal, struct key_v4, int);
BPF_LPM_TRIE(ipv6_allow_list_trusted_external, struct key_v4, int);

// Below can be used to configure per customized access control list associate with applcation
BPF_LPM_TRIE(ipv6_allow_list_s1, struct key_v4, int);
BPF_LPM_TRIE(ipv6_allow_list_s2, struct key_v4, int);
BPF_LPM_TRIE(ipv6_allow_list_s3, struct key_v4, int);
BPF_LPM_TRIE(ipv6_allow_list_s4, struct key_v4, int);
BPF_LPM_TRIE(ipv6_allow_list_s5, struct key_v4, int);

// Per application set level access control, white list based
BPF_HASH_OF_MAPS(app_ipv4_strict_access_list, struct task_info, "ipv4_allow_list", MAXIMUM_LEN_OF_APP_ACCESS_LIST);


// Per application set level access control, white list based
BPF_HASH_OF_MAPS(app_ipv6_strict_access_list, struct task_info, "ipv6_allow_list", MAXIMUM_LEN_OF_APP_ACCESS_LIST);


// Maximum layer trace to parent process id
#define MAXIMUM_LOOP 20

static __always_inline int compare_comm_str(char *cur_comm, char *tar_comm) {
    #pragma clang loop unroll(full)
    for (int i = 0; i < 16; i++) {
        if (*(cur_comm+i) != *(tar_comm+i)) {
            return -1;
        }

        if (*(cur_comm+i) == *(tar_comm+i) && *(cur_comm+i) == 0) {
            return 0;
        }
    }

    return 0;
}

/// @brief recursive track the process tree
/// @param tar_comm 
/// @return 
static __always_inline int trace_process_to_comm(char *tar_comm) {
    struct task_struct *cur_task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent_task = NULL;
    pid_t cur_pid;
    char cur_comm[16];

    if (cur_task == NULL) {
        return -ENAVAIL;
    }

    if (bpf_probe_read_kernel_str(cur_comm, sizeof(cur_comm), cur_task->comm) < 0) {
        return -ENAVAIL;
    }

    if (!compare_comm_str(cur_comm, tar_comm)) {
        return 0;
    }

    #pragma clang loop unroll(full)
    for (int i = 0; i < MAXIMUM_LOOP; i++) {
        if (bpf_probe_read_kernel(&parent_task, sizeof(parent_task), &cur_task->real_parent) != 0) {
            return -ENAVAIL;
        } else {
            cur_task = parent_task;
            if (bpf_probe_read_kernel(&cur_pid, sizeof(cur_pid), &cur_task->pid) !=0 ) {
                return -ENAVAIL;
            }
            
            if (cur_pid == 1) {
                return -ENAVAIL;
            }

            if (bpf_probe_read_kernel_str(cur_comm, sizeof(cur_comm), cur_task->comm) != 0) {
                return -ENAVAIL;
            }

            if (!compare_comm_str(cur_comm, tar_comm)) {
                return 0;
            }
        }
    }

    return -ENAVAIL;
}

#define IPV4 1
#define IPV6 2

/// @brief find associate application level allow target TRIE IP table
/// @param ip_v 
/// @param tar_comm 
/// @return ptr to allow ip TRIE table
static __always_inline void* find_app_access_list(int ip_v, char *tar_comm) {
    struct task_struct *cur_task = (struct task_struct *)bpf_get_current_task();
    struct task_info task_comm;
    struct exec_file_name *cur_exec_file_name = NULL;
    pid_t cur_pid;

    if (cur_task == NULL) {
        return (void *)-1;
    }

    int key = 0;
    cur_exec_file_name = cur_exe_file_name_array.lookup(&key);
    if (cur_exec_file_name == NULL) {
        return (void *)-1;
    }

    if (ebpf_get_task_exec_file(cur_task, cur_exec_file_name) != 0) {
        // This shall direct reject the connection
        bpf_probe_read_kernel(&cur_pid, sizeof(cur_pid), &cur_task->pid);
        return (void *)-1;
    } else {
        ebpf_memset((char *)&task_comm, 0, sizeof(task_comm));
        ebpf_strncpy(task_comm.comm, cur_exec_file_name->small_name, sizeof(task_comm.comm));
    }

    ebpf_strncpy(tar_comm, task_comm.comm, sizeof(task_comm.comm));

#ifdef DEBUG
    bpf_trace_printk("Find app %s from strict access list", task_comm.comm);
#endif

    if (ip_v == IPV4) {
        return app_ipv4_strict_access_list.lookup(&task_comm);
    } else if (ip_v == IPV6) {
        return app_ipv6_strict_access_list.lookup(&task_comm);
    }

    return (void *)-1;
}

// Connect firewall, per application controlling
LSM_PROBE(socket_connect, struct socket *sock, struct sockaddr *address, int addrlen) {
    u32 *entry = NULL;
    char tar_comm[16];
    pid_t cur_pid;
    struct task_struct *cur_task = (struct task_struct *)bpf_get_current_task();

    ebpf_memset(tar_comm, 0, sizeof(tar_comm));
    bpf_probe_read_kernel(&cur_pid, sizeof(cur_pid), &cur_task->pid);

    if (address->sa_family == AF_INET) {

#ifdef DEBUG
        bpf_trace_printk("IPV4 Socket CONNECT SECURITY FILTER %d", cur_pid);
#endif

        struct sockaddr_in *inet_addr = (struct sockaddr_in *)address;
        struct key_v4 key = {
            .prefixlen = 32,
            .data = inet_addr->sin_addr.s_addr,
        };

        entry = host_ipv4_allow_list.lookup(&key);
        if (entry == NULL) {
            struct ebpf_event *event = lsm_events.ringbuf_reserve(sizeof(struct ebpf_event));
            if (event != NULL) {
                char app_name[32];
                initialize_ebpf_event_log(event, "socket_connect");
                put_ebpf_event_log(event, "IPV4_Host_Block", 17, TYPE_STR);
                if (ebpf_get_current_task_app_name(app_name, sizeof(app_name)) != 0) {
                    lsm_events.ringbuf_discard(event, 0);
                    return -EACCES;
                }
                put_ebpf_event_log(event, (const char *)&key.data, sizeof(key.data), TYPE_IPV4);
                put_ebpf_event_log(event, app_name, ebpf_strnlen(app_name, sizeof(app_name)), TYPE_STR);
                lsm_events.ringbuf_submit(event, 0);
            }
            return -EPERM;
        }

        void *access_list = NULL;
        access_list = find_app_access_list(IPV4, tar_comm);
        if (access_list == (void *)-1) {
            // Exception case
            return -EPERM;
        } else if (access_list != NULL) {
            entry = bpf_map_lookup_elem(access_list, &key);
            if (entry == NULL) {
                struct ebpf_event *event = lsm_events.ringbuf_reserve(sizeof(struct ebpf_event));
                if (event != NULL) {
                    initialize_ebpf_event_log(event, "socket_connect");
                    put_ebpf_event_log(event, "IPV4_App_Block", 15, TYPE_STR);
                    put_ebpf_event_log(event, (const char *)&key.data, sizeof(key.data), TYPE_IPV4);
                    put_ebpf_event_log(event, tar_comm, ebpf_strnlen(tar_comm, sizeof(tar_comm)), TYPE_STR);
                    lsm_events.ringbuf_submit(event, 0);
                }

#ifdef DEBUG
                bpf_trace_printk("IPV4 Socket CONNECT rejected %d\r\n", cur_pid);
#endif  
                return -EPERM;
            }
        }

#ifdef DEBUG
        bpf_trace_printk("IPV4 Socket CONNECT Passed %d\r\n", cur_pid);
#endif

    } else if (address->sa_family == AF_INET6) {

#ifdef DEBUG
        bpf_trace_printk("IPV6 Socket CONNECT SECURITY FILTER %d", cur_pid);
#endif

        struct sockaddr_in6 * inet_addr6 = (struct sockaddr_in6 *)address;
        
        struct key_v6 key;
        key.prefixlen = 128;
        bpf_probe_read_kernel(key.data, sizeof(struct in6_addr), inet_addr6->sin6_addr.s6_addr32);

        entry = host_ipv6_allow_list.lookup(&key);
        if (entry == NULL) {
            struct ebpf_event *event = lsm_events.ringbuf_reserve(sizeof(struct ebpf_event));
            if (event != NULL) {
                char app_name[32];
                initialize_ebpf_event_log(event, "socket_connect");
                put_ebpf_event_log(event, "IPV6_Host_Block", 16, TYPE_STR);
                if (ebpf_get_current_task_app_name(app_name, sizeof(app_name)) != 0) {
                    lsm_events.ringbuf_discard(event, 0);
                    return -EACCES;
                }
                put_ebpf_event_log(event, (const char *)&key.data, sizeof(key.data), TYPE_IPV6);
                put_ebpf_event_log(event, app_name, ebpf_strnlen(app_name, sizeof(app_name)), TYPE_STR);
                lsm_events.ringbuf_submit(event, 0);
            }

            return -EPERM;
        }

        void *access_list = NULL;
        access_list = find_app_access_list(IPV6, tar_comm);
        if (access_list == (void *)-1) {
            return -EPERM;
        } else if (access_list != NULL) {
            entry = bpf_map_lookup_elem(access_list, &key);
            if (entry == NULL) {
                struct ebpf_event *event = lsm_events.ringbuf_reserve(sizeof(struct ebpf_event));
                if (event != NULL) {
                    initialize_ebpf_event_log(event, "socket_connect");
                    put_ebpf_event_log(event, "IPV6_App_Block", 15, TYPE_STR);
                    put_ebpf_event_log(event, (const char *)&key.data, sizeof(key.data), TYPE_IPV6);
                    put_ebpf_event_log(event, tar_comm, ebpf_strnlen(tar_comm, sizeof(tar_comm)), TYPE_STR);
                    lsm_events.ringbuf_submit(event, 0);
                }

#ifdef DEBUG
                bpf_trace_printk("IPV6 Socket CONNECT rejected %d\r\n", cur_pid);
#endif  
                return -EPERM;
            }
        }

#ifdef DEBUG
        bpf_trace_printk("IPV6 Socket CONNECT Passed %d\r\n", cur_pid);
#endif

    }

    return 0;
}

/// @brief In case not initiated TCP connection from socket connect
/// @param  
/// @param sk 
/// @param skb 
LSM_PROBE(inet_conn_established, struct sock *sk, struct sk_buff *skb) {
    u32 *entry = NULL;

    if (sk->sk_family == AF_INET) {
        struct key_v4 key = {
            .prefixlen = 32,
            .data = 0,
        };

        if (bpf_probe_read_kernel(&key.data, sizeof(key.data), &sk->sk_daddr) != 0) {
            return -EACCES;
        }

        entry = host_ipv4_allow_list.lookup(&key);
        if (entry == NULL) {            
            struct ebpf_event *event = lsm_events.ringbuf_reserve(sizeof(struct ebpf_event));
            if (event != NULL) {
                initialize_ebpf_event_log(event, "inet_conn_established");
                put_ebpf_event_log(event, (const char*)&key.data, sizeof(key.data), TYPE_IPV4);
                put_ebpf_event_log(event, "TCPv4_Host_Block", 17, TYPE_STR);
                lsm_events.ringbuf_submit(event, 0);
            }

            return -EPERM;
        }

    } else if (sk->sk_family == AF_INET6) {
        struct key_v6 key;
        key.prefixlen = 128;

        if (bpf_probe_read_kernel(&key.data, sizeof(key.data), &sk->sk_v6_daddr.s6_addr32) != 0) {
            return -EACCES;
        }

        entry = host_ipv6_allow_list.lookup(&key);
        if (entry == NULL) {
            struct ebpf_event *event = lsm_events.ringbuf_reserve(sizeof(struct ebpf_event));
            
            if (event != NULL) {
                initialize_ebpf_event_log(event, "inet_conn_established");
                put_ebpf_event_log(event, (const char*)&key.data, sizeof(key.data), TYPE_IPV6);
                put_ebpf_event_log(event, "TCPv6_Host_Block", 17, TYPE_STR);
                lsm_events.ringbuf_submit(event, 0);
            }

            return -EPERM;
        }
    }

    return 0;
}

/// @brief  sendto check with configured target IP
/// @param  
/// @param sock 
/// @param msg 
/// @param size 
LSM_PROBE(socket_sendmsg, struct socket *sock, struct msghdr *msg, int size) {
    u32 *entry = NULL;

    if (sock->type == SOCK_DGRAM) {
        if (msg->msg_name != NULL) {
            struct sockaddr_storage addrs;

            if (bpf_probe_read_kernel(&addrs, sizeof(addrs), msg->msg_name) != 0) {
                return -EACCES;
            }
            
            struct sockaddr *addr = (struct sockaddr *)&addrs;

            if (addr->sa_family == AF_INET) {
                struct sockaddr_in *inet_addr = (struct sockaddr_in *)addr;
                struct key_v4 key = {
                    .prefixlen = 32,
                    .data = inet_addr->sin_addr.s_addr,
                };

                entry = host_ipv4_allow_list.lookup(&key);
                if (entry == NULL) {
                    struct ebpf_event *event = lsm_events.ringbuf_reserve(sizeof(struct ebpf_event));
                    
                    if (event != NULL) {
                        char app_name[32];
                        initialize_ebpf_event_log(event, "socket_sendmsg");
                        put_ebpf_event_log(event, "UDPv4_Host_Block", 17, TYPE_STR);
                        if (ebpf_get_current_task_app_name(app_name, sizeof(app_name)) != 0) {
                            lsm_events.ringbuf_discard(event, 0);
                            return -EACCES;
                        }
                        put_ebpf_event_log(event, (const char*)&key.data, sizeof(key.data), TYPE_IPV4);
                        put_ebpf_event_log(event, app_name, ebpf_strnlen(app_name, sizeof(app_name)), TYPE_STR);
                        lsm_events.ringbuf_submit(event, 0);
                    }

                    return -EPERM;
                }

            } else if (addr->sa_family == AF_INET6) {
                struct sockaddr_in6 * inet_addr6 = (struct sockaddr_in6 *)addr;
        
                struct key_v6 key;
                key.prefixlen = 128;
                ebpf_memncpy((char *)key.data, (const char *)inet_addr6->sin6_addr.s6_addr32, sizeof(struct in6_addr), sizeof(struct in6_addr));

                entry = host_ipv6_allow_list.lookup(&key);
                if (entry == NULL) {
                    struct ebpf_event *event = lsm_events.ringbuf_reserve(sizeof(struct ebpf_event));
                    if (event != NULL) {
                        char app_name[32];
                        initialize_ebpf_event_log(event, "socket_sendmsg");
                        put_ebpf_event_log(event, "UDPv6_Host_Block", 17, TYPE_STR);
                        if (ebpf_get_current_task_app_name(app_name, sizeof(app_name)) != 0) {
                            lsm_events.ringbuf_discard(event, 0);
                            return -EACCES;
                        }
                        put_ebpf_event_log(event, (const char*)&key.data, sizeof(key.data), TYPE_IPV6);
                        put_ebpf_event_log(event, app_name, ebpf_strnlen(app_name, sizeof(app_name)), TYPE_STR);
                        lsm_events.ringbuf_submit(event, 0);
                    }

                    return -EPERM;
                }
            }
        }
    }

    return 0;
}


/// @brief Unix stream connect security control, TODO security control
/// @param  
/// @param sock 
/// @param other 
/// @param newsk 
LSM_PROBE(unix_stream_connect, struct sock *sock, struct sock *other, struct sock *newsk) {
    struct unix_sock *otherru = unix_sk(other);
    struct dentry *dentry = NULL;
    bool failed = 0;

    char sock_name[32];
    struct qstr unix_sock_name;
    ebpf_memset(sock_name, 0, sizeof(sock_name));

    if (bpf_probe_read_kernel(&dentry, sizeof(dentry), &otherru->path.dentry) != 0) {
        ebpf_strncpy(sock_name, "unknown_sock1", 14);
        failed = 1;
    }

    if (!failed) {    
        if (bpf_probe_read_kernel(&unix_sock_name, sizeof(unix_sock_name), &dentry->d_name) != 0) {
            ebpf_strncpy(sock_name, "unknown_sock2", 14);    
            failed = 1;
        }
    }

    if (!failed) {
        if (bpf_probe_read_kernel_str(sock_name, sizeof(sock_name), unix_sock_name.name) < 0) {
            ebpf_strncpy(sock_name, "unknown_sock3", 14);
        }
    }

    struct ebpf_event *event = lsm_events.ringbuf_reserve(sizeof(struct ebpf_event));
    if (event != NULL) {
        initialize_ebpf_event_log(event, "unix_stream_connect");
        put_ebpf_event_log(event, sock_name, ebpf_strnlen(sock_name, sizeof(sock_name)), TYPE_STR);
        char app_name[32];
        if (ebpf_get_current_task_app_name(app_name, sizeof(app_name)) != 0) {
            ebpf_strncpy(app_name, "unknown_app", 12);
        }
        put_ebpf_event_log(event, app_name, ebpf_strnlen(app_name, sizeof(app_name)), TYPE_STR);
        lsm_events.ringbuf_submit(event, 0);
    }

    return 0;
}


/// @brief unix dgram connect/send, TODO security control
/// @param  
/// @param sock 
/// @param other 
LSM_PROBE(unix_may_send, struct socket *sock, struct socket *other) {
    struct unix_sock *otherru = unix_sk(other->sk);
    struct dentry *dentry = NULL;
    bool failed = 0;

    struct qstr unix_sock_name;
    char sock_name[32];
    ebpf_memset(sock_name, 0, sizeof(sock_name));

    if (bpf_probe_read_kernel(&dentry, sizeof(dentry), &otherru->path.dentry) != 0) {
        ebpf_strncpy(sock_name, "unknown_sock1", 14);
        failed = 1;
    }

    if (!failed) {
        if (bpf_probe_read_kernel(&unix_sock_name, sizeof(unix_sock_name), &dentry->d_name) != 0) {
            ebpf_strncpy(sock_name, "unknown_sock2", 14);    
            failed = 1;
        }
    }

    if (!failed) {
        if (bpf_probe_read_kernel_str(sock_name, sizeof(sock_name), unix_sock_name.name) < 0) {
            ebpf_strncpy(sock_name, "unknown_sock3", 14);
        }
    }

    struct ebpf_event *event = lsm_events.ringbuf_reserve(sizeof(struct ebpf_event));
    if (event != NULL) {
        initialize_ebpf_event_log(event, "unix_may_send");
        put_ebpf_event_log(event, sock_name, ebpf_strnlen(sock_name, sizeof(sock_name)), TYPE_STR);
        char app_name[32];
        if (ebpf_get_current_task_app_name(app_name, sizeof(app_name)) != 0) {
            ebpf_strncpy(app_name, "unknown_app", 12);
        }
        put_ebpf_event_log(event, app_name, ebpf_strnlen(app_name, sizeof(app_name)), TYPE_STR);
        lsm_events.ringbuf_submit(event, 0);
    }

    return 0;
}


/// @brief > 1024 port require extra checking
/// @param  
/// @param  
/// @param  
BPF_HASH(tcp_allowed_high_port, u16, struct task_info);
BPF_HASH(udp_allowed_high_port, u16, struct task_info);
BPF_HASH(tcp_allowed_ephemeral_port_listen, struct task_info, u32);

#define HIGH_PORT_START 1024

/// @brief 
/// @param  
/// @param sock 
/// @param backlog 
LSM_PROBE(socket_listen, struct socket *sock, int backlog) {
    struct sock *sk = (struct sock *)sock->sk;
    u16 port = sk->sk_num;

    if (sock->type == SOCK_STREAM) {
        if (port < HIGH_PORT_START) {
            return 0;
        }
    } else {
        return 0;
    }

    struct task_info current_task;
    ebpf_memset(current_task.comm, 0, sizeof(current_task.comm));
    if (ebpf_get_current_task_app_name(current_task.comm, sizeof(current_task.comm)) != 0) {
        return -EACCES;
    }

    void *entry = NULL;
    entry = tcp_allowed_ephemeral_port_listen.lookup(&current_task);
    if (entry != NULL) {
        return 0;
    }

    entry = tcp_allowed_high_port.lookup(&port);
    if (entry != NULL) {
        struct task_info *task = (struct task_info *)entry;
        if (ebpf_strncmp(current_task.comm, task->comm, sizeof(current_task.comm)) == 0) {
            return 0;
        }
    }

    struct ebpf_event *event = lsm_events.ringbuf_reserve(sizeof(struct ebpf_event));
    if (event != NULL) {
        initialize_ebpf_event_log(event, "socket_listen");
        put_ebpf_event_log(event, current_task.comm, sizeof(current_task.comm), TYPE_STR);
        put_ebpf_event_log(event, "TCP", 4, TYPE_STR);
        put_ebpf_event_log(event, (const char *)&port, sizeof(port), TYPE_U16);
        lsm_events.ringbuf_submit(event, 0);
    }

    return -EPERM;
}


/// @brief Not allow bind to port > 1024 except it is register in the list
/// @param  
/// @param sock 
/// @param address 
/// @param addrlen 
LSM_PROBE(socket_bind, struct socket *sock, struct sockaddr *address, int addrlen) {
    u16 sock_type = sock->type;
    u16 port;

    if (address->sa_family == AF_INET || address->sa_family == AF_INET6) {
        struct sockaddr_in *inet_addr = (struct sockaddr_in *)address;
        port = bpf_ntohs(inet_addr->sin_port);

        if (port < HIGH_PORT_START) {
            return 0;
        }
    } else {
        return 0;
    }

    struct task_info current_task;
    ebpf_memset(current_task.comm, 0, sizeof(current_task.comm));
    if (ebpf_get_current_task_app_name(current_task.comm, sizeof(current_task.comm)) != 0) {
        return -EACCES;
    }

    void *entry = NULL;
    if (sock_type == SOCK_STREAM) {
        entry = tcp_allowed_high_port.lookup(&port);
    } else if (sock_type == SOCK_DGRAM) {
        entry = udp_allowed_high_port.lookup(&port);
    } else {
        return 0;
    }

    if (entry != NULL) {
        struct task_info *task = (struct task_info *)entry;
        if (ebpf_strncmp(current_task.comm, task->comm, sizeof(current_task.comm)) == 0) {
            return 0;
        }
    }

    struct ebpf_event *event = lsm_events.ringbuf_reserve(sizeof(struct ebpf_event));
    if (event != NULL) {
        initialize_ebpf_event_log(event, "socket_bind");
        put_ebpf_event_log(event, current_task.comm, sizeof(current_task.comm), TYPE_STR);
        if (sock_type == SOCK_STREAM) {
            put_ebpf_event_log(event, "TCP", 4, TYPE_STR);
        } else if (sock_type == SOCK_DGRAM) {
            put_ebpf_event_log(event, "UDP", 4, TYPE_STR);
        }
        put_ebpf_event_log(event, (const char *)&port, sizeof(port), TYPE_U16);
        lsm_events.ringbuf_submit(event, 0);
    }

    return -EPERM;
}


/// @brief RAW Socket Create control
/// @param  
/// @param family 
/// @param type  SOCK_RAW
/// @param protocol  IPPROTO_ETHERNET, IPPROTO_RAW, IPPROTO_IP
/// @param kern 
LSM_PROBE(socket_create, int family, int type, int protocol, int kern) {
    return 0;
    struct ebpf_event *event = lsm_events.ringbuf_reserve(sizeof(struct ebpf_event));
                    
    if (event != NULL) {
        char app_name[32];
        initialize_ebpf_event_log(event, "socket_create");
        if (ebpf_get_current_task_app_name(app_name, sizeof(app_name)) != 0) {
            lsm_events.ringbuf_discard(event, 0);
            return -EACCES;
        }
        put_ebpf_event_log(event, app_name, ebpf_strnlen(app_name, sizeof(app_name)), TYPE_STR);
    } else {
        return -EACCES;
    }
    
    // TODO configurable 
    if (family != PF_INET || family != PF_INET6 || family != PF_UNIX || family != PF_NETLINK) {
        put_ebpf_event_log(event, (const char *)&family, sizeof(family), TYPE_I32);
        lsm_events.ringbuf_submit(event, 0);
        return -EPERM;
    }

    int need_further_check = 0;
    if (type != SOCK_DGRAM && type != SOCK_PACKET && type != SOCK_STREAM && type != SOCK_SEQPACKET) {
        need_further_check = 1;
    }

    if (need_further_check) {
        if (protocol != IPPROTO_ICMP && protocol != IPPROTO_IGMP) {
            put_ebpf_event_log(event, (const char *)&type, sizeof(type), TYPE_I32);
            put_ebpf_event_log(event, (const char *)&protocol, sizeof(protocol), TYPE_I32);
            lsm_events.ringbuf_submit(event, 0);
            return -EPERM;
        }
    }

    return 0;
}
