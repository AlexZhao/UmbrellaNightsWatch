// SPDX-License-Identifier: 2023
// Copyright Alex Zhao
//
// Security Control for Netlink 
//   1. netfilter
//   2. iptable
//   3. rtnl  
//   4. generic 
// All kernel network related configuration  
// and notifications   
#include <linux/errno.h>
#include <linux/skbuff.h>
#include <linux/netlink.h>
#include <linux/bpf.h>

// nlmsg type 
#include <linux/rtnetlink.h>           // RTM  NETLINK_ROUTE
#include <linux/netfilter/nfnetlink.h> // NFNL   NETLINK_NETFILTER
#include <linux/xfrm.h>                // XFRM NETLINK_XFRM

#include <linux/socket.h>  // struct msghdr {}

#include <net/sock.h>
#include <../net/netlink/af_netlink.h>

#include "ebpf/ebpf_event.h"
#include "ebpf/ebpf_exe.h"
#include "ebpf/ebpf_str.h"

BPF_RINGBUF_OUTPUT(lsm_events, 8);

// simple comm to identify task, it shall use task_struct with 
// executable file and credential
struct task_info {
    char comm[16];
};

// Basic RW access control 
// RTM_GET  RTM_NEW/DEL/SET   
static int netlink_parse_route(struct sk_buff *skb) {
    return 0;    
}
 
static int netlink_parse_xfrm(struct sk_buff *skb) {
    return 0;
}

static int netlink_parse_netfilter(struct sk_buff *skb) {
    return 0;
}





/// @brief netlink security control checking
/// @return 
static int netlink_security_check() {
    return 0;
}

//
//#define NETLINK_ROUTE		0	/* Routing/device hook				*/
//#define NETLINK_UNUSED		1	/* Unused number				*/
//#define NETLINK_USERSOCK	2	/* Reserved for user mode socket protocols 	*/
//#define NETLINK_FIREWALL	3	/* Unused number, formerly ip_queue		*/
//#define NETLINK_SOCK_DIAG	4	/* socket monitoring				*/
//#define NETLINK_NFLOG		5	/* netfilter/iptables ULOG */
//#define NETLINK_XFRM		6	/* ipsec */
//#define NETLINK_SELINUX		7	/* SELinux event notifications */
//#define NETLINK_ISCSI		8	/* Open-iSCSI */
//#define NETLINK_AUDIT		9	/* auditing */
//#define NETLINK_FIB_LOOKUP	10	
//#define NETLINK_CONNECTOR	11
//#define NETLINK_NETFILTER	12	/* netfilter subsystem */
//#define NETLINK_IP6_FW		13
//#define NETLINK_DNRTMSG		14	/* DECnet routing messages (obsolete) */
//#define NETLINK_KOBJECT_UEVENT	15	/* Kernel messages to userspace */
//#define NETLINK_GENERIC		16
/* leave room for NETLINK_DM (DM Events) */
//#define NETLINK_SCSITRANSPORT	18	/* SCSI Transports */
//#define NETLINK_ECRYPTFS	19
//#define NETLINK_RDMA		20
//#define NETLINK_CRYPTO		21	/* Crypto layer */
//#define NETLINK_SMC		22	/* SMC monitoring */
/// @brief netlink controlling hook 
/// @param  
/// @param sk 
/// @param skb 
LSM_PROBE(netlink_send, struct sock *sk, struct sk_buff *skb) {
    struct netlink_sock *nlk = nlk_sk(sk);
    int protocol = sk->sk_protocol;
    int errno = 0;

    struct task_info app_name;
    ebpf_memset(app_name.comm, 0, sizeof(app_name));
    if (ebpf_get_current_task_app_name(app_name.comm, sizeof(app_name)) != 0) {
        errno = -EACCES;
    }

    // netlink MAC controlling here, need to loop multi netlink msg in single send
    // not able to use skb_pull(), need to move ptr, this move to per NETLINK_PROTO
    // parsing based on tail call 
    if (skb->len >= nlmsg_total_size(0)) {
        struct nlmsghdr *nlh = nlmsg_hdr(skb); // skb->data, first start nlmsg hdr
        int type = nlh->nlmsg_type;
        int msglen = NLMSG_ALIGN(nlh->nlmsg_len);
    }

    char netlink_type[32];
    ebpf_memset(netlink_type, 0, sizeof(netlink_type));
    switch (protocol) {
        case NETLINK_ROUTE:
            errno = netlink_parse_route(skb);
            ebpf_strncpy(netlink_type, "netlink_route", 14);
            break;
        case NETLINK_UNUSED:
            ebpf_strncpy(netlink_type, "netlink_unused", 15);
            break;
        case NETLINK_USERSOCK:
            ebpf_strncpy(netlink_type, "netlink_usersock", 17);
            break;
        case NETLINK_FIREWALL:
            ebpf_strncpy(netlink_type, "netlink_firewall", 17);
            break;
        case NETLINK_SOCK_DIAG:
            ebpf_strncpy(netlink_type, "netlink_sock_diag", 18);
            break;
        case NETLINK_NFLOG:
            ebpf_strncpy(netlink_type, "netlink_nflog", 14);
            break;
        case NETLINK_XFRM:
            errno = netlink_parse_xfrm(skb); 
            ebpf_strncpy(netlink_type, "netlink_xfrm", 13);
            break;
        case NETLINK_SELINUX:
            ebpf_strncpy(netlink_type, "netlink_selinux", 16);
            break;
        case NETLINK_ISCSI:
            ebpf_strncpy(netlink_type, "netlink_iscsi", 14);
            break;
        case NETLINK_AUDIT:
            ebpf_strncpy(netlink_type, "netlink_audit", 14);
            break;
        case NETLINK_FIB_LOOKUP:
            ebpf_strncpy(netlink_type, "netlink_fib_lookup", 19);
            break;
        case NETLINK_CONNECTOR:
            ebpf_strncpy(netlink_type, "netlink_connector", 18);
            break;
        case NETLINK_NETFILTER:
            errno = netlink_parse_netfilter(skb);
            ebpf_strncpy(netlink_type, "netlink_netfilter", 18);
            break;
        case NETLINK_IP6_FW:
            ebpf_strncpy(netlink_type, "netlink_ip6_fw", 15);
            break;
        case NETLINK_DNRTMSG:
            ebpf_strncpy(netlink_type, "netlink_dnrtmsg", 16);
            break;
        case NETLINK_SCSITRANSPORT:
            ebpf_strncpy(netlink_type, "netlink_scsitransport", 22);
            break;
        case NETLINK_ECRYPTFS:
            ebpf_strncpy(netlink_type, "netlink_ecryptfs", 17);
            break;
        case NETLINK_RDMA:
            ebpf_strncpy(netlink_type, "netlink_rdma", 13);
            break;
        case NETLINK_CRYPTO:
            ebpf_strncpy(netlink_type, "netlink_crypto", 15);
            break;
        case NETLINK_SMC:
            ebpf_strncpy(netlink_type, "netlink_smc", 12);
            break;
        default:
            ebpf_strncpy(netlink_type, "netlink_unknow", 15);
            errno = -EPERM;
            break;
    }

    struct ebpf_event *event = lsm_events.ringbuf_reserve(sizeof(struct ebpf_event));
    if (event != NULL) {
        initialize_ebpf_event_log(event, "netlink_send");
        put_ebpf_event_log(event, app_name.comm, ebpf_strnlen(app_name.comm, sizeof(app_name.comm)), TYPE_STR);
        put_ebpf_event_log(event, netlink_type, ebpf_strnlen(netlink_type, sizeof(netlink_type)), TYPE_STR);
        if (!errno) {
            put_ebpf_event_log(event, "allow", 6, TYPE_STR);
        } else {
            put_ebpf_event_log(event, "block", 6, TYPE_STR);
        }
        lsm_events.ringbuf_submit(event, 0);
    }

    return errno;
}