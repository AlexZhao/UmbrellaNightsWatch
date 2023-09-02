// SPDX-License-Identifier: 2023
// Copyright Zhao Zhe (Alex)
//
// IP tunnel based xfrm
// ESP/AH/ROUTE2/HAO/....
//
// default disable all IPSec/.... tunnel
// vti_rcv_cb
// ipip, ipip6, ipcomp4, esp, ah 
#include <linux/errno.h>
#include <linux/skbuff.h>
#include <linux/xfrm.h>
#include <linux/types.h>
#include <linux/ip.h>

#include <linux/netdevice.h>

#include <net/xfrm.h>
#include <net/flow.h>

#include "ebpf/ebpf_exe.h"
#include "ebpf/ebpf_str.h"
#include "ebpf/ebpf_event.h"

BPF_RINGBUF_OUTPUT(lsm_events, 4);

LSM_PROBE(xfrm_policy_alloc_security, struct xfrm_sec_ctx **ctxp,
	 struct xfrm_user_sec_ctx *sec_ctx, gfp_t gfp) {

    struct ebpf_event *event = lsm_events.ringbuf_reserve(sizeof(struct ebpf_event));
    if (event == NULL) {
        return -EACCES;
    }
    initialize_ebpf_event_log(event, "xfrm_pol_alloc");
    
    char app_name[32];
    ebpf_memset(app_name, 0, sizeof(app_name));
    ebpf_get_current_task_app_name(app_name, sizeof(app_name));
    put_ebpf_event_log(event, app_name, sizeof(app_name), TYPE_STR);
    lsm_events.ringbuf_submit(event, 0);
    
    return -EPERM;
}

LSM_PROBE(xfrm_policy_clone_security, struct xfrm_sec_ctx *old_ctx,
	 struct xfrm_sec_ctx **new_ctx) {

    struct ebpf_event *event = lsm_events.ringbuf_reserve(sizeof(struct ebpf_event));
    if (event == NULL) {
        return -EACCES;
    }
    initialize_ebpf_event_log(event, "xfrm_pol_clone");
    
    char app_name[32];
    ebpf_memset(app_name, 0, sizeof(app_name));
    ebpf_get_current_task_app_name(app_name, sizeof(app_name));
    put_ebpf_event_log(event, app_name, sizeof(app_name), TYPE_STR);
    lsm_events.ringbuf_submit(event, 0);

    return -EPERM;
}

LSM_PROBE(xfrm_policy_delete_security, struct xfrm_sec_ctx *sec_ctx) {

    struct ebpf_event *event = lsm_events.ringbuf_reserve(sizeof(struct ebpf_event));
    if (event == NULL) {
        return -EACCES;
    }
    initialize_ebpf_event_log(event, "xfrm_pol_delete");
    
    char app_name[32];
    ebpf_memset(app_name, 0, sizeof(app_name));
    ebpf_get_current_task_app_name(app_name, sizeof(app_name));
    put_ebpf_event_log(event, app_name, sizeof(app_name), TYPE_STR);
    lsm_events.ringbuf_submit(event, 0);

    return -EPERM;
}

LSM_PROBE(xfrm_state_alloc, struct xfrm_state *x,
	 struct xfrm_user_sec_ctx *sec_ctx) {

    struct ebpf_event *event = lsm_events.ringbuf_reserve(sizeof(struct ebpf_event));
    if (event == NULL) {
        return -EACCES;
    }
    initialize_ebpf_event_log(event, "xfrm_state_alloc");
    
    char app_name[32];
    ebpf_memset(app_name, 0, sizeof(app_name));
    ebpf_get_current_task_app_name(app_name, sizeof(app_name));
    put_ebpf_event_log(event, app_name, sizeof(app_name), TYPE_STR);
    lsm_events.ringbuf_submit(event, 0);

    return -EPERM;
}

LSM_PROBE(xfrm_state_alloc_acquire, struct xfrm_state *x,
	 struct xfrm_sec_ctx *polsec, u32 secid) {

    struct ebpf_event *event = lsm_events.ringbuf_reserve(sizeof(struct ebpf_event));
    if (event == NULL) {
        return -EACCES;
    }
    initialize_ebpf_event_log(event, "xfrm_state_alloc_ac");
    
    char app_name[32];
    ebpf_memset(app_name, 0, sizeof(app_name));
    ebpf_get_current_task_app_name(app_name, sizeof(app_name));
    put_ebpf_event_log(event, app_name, sizeof(app_name), TYPE_STR);
    lsm_events.ringbuf_submit(event, 0);

    return -EPERM;
}

LSM_PROBE(xfrm_state_delete_security, struct xfrm_state *x) {
    struct ebpf_event *event = lsm_events.ringbuf_reserve(sizeof(struct ebpf_event));
    if (event == NULL) {
        return -EACCES;
    }
    initialize_ebpf_event_log(event, "xfrm_state_delete");
    
    char app_name[32];
    ebpf_memset(app_name, 0, sizeof(app_name));
    ebpf_get_current_task_app_name(app_name, sizeof(app_name));
    put_ebpf_event_log(event, app_name, sizeof(app_name), TYPE_STR);
    lsm_events.ringbuf_submit(event, 0);

    return -EPERM;
}

LSM_PROBE(xfrm_policy_lookup, struct xfrm_sec_ctx *sec_ctx, u32 fl_secid) {
    struct ebpf_event *event = lsm_events.ringbuf_reserve(sizeof(struct ebpf_event));
    if (event == NULL) {
        return -EACCES;
    }
    initialize_ebpf_event_log(event, "xfrm_pol_lookup");
    
    char app_name[32];
    ebpf_memset(app_name, 0, sizeof(app_name));
    ebpf_get_current_task_app_name(app_name, sizeof(app_name));
    put_ebpf_event_log(event, app_name, sizeof(app_name), TYPE_STR);
    lsm_events.ringbuf_submit(event, 0);

    return -EPERM;
}

LSM_PROBE(xfrm_state_pol_flow_match, struct xfrm_state *x,
	 struct xfrm_policy *xp, const struct flowi_common *flic) {

    struct ebpf_event *event = lsm_events.ringbuf_reserve(sizeof(struct ebpf_event));
    if (event == NULL) {
        return -EACCES;
    }
    initialize_ebpf_event_log(event, "xfrm_state_pol_flow");
    
    char app_name[32];
    ebpf_memset(app_name, 0, sizeof(app_name));
    ebpf_get_current_task_app_name(app_name, sizeof(app_name));
    put_ebpf_event_log(event, app_name, sizeof(app_name), TYPE_STR);
    lsm_events.ringbuf_submit(event, 0);

    return -EPERM;
}



/// @brief  Trigger system restart which shall not
/// @param  
/// @param skb 
/// @param secid 
/// @param ckall 
LSM_PROBE(xfrm_decode_session, struct sk_buff *skb, u32 *secid,
	 int ckall) {

    struct ebpf_event *event = lsm_events.ringbuf_reserve(sizeof(struct ebpf_event));
    if (event == NULL) {
        return -EACCES;
    }
    initialize_ebpf_event_log(event, "xfrm_decode_ses");

    struct net_device *dev;
    bpf_probe_read(&dev, sizeof(skb->dev), ((char *)skb + offsetof(struct sk_buff, dev)));
    char dev_name[IFNAMSIZ];
    bpf_probe_read(dev_name, IFNAMSIZ, dev->name);
    put_ebpf_event_log(event, dev_name, ebpf_strnlen(dev_name, sizeof(dev_name)), TYPE_STR);

    struct iphdr *ip = ip_hdr(skb);    
    struct iphdr iph;
    bpf_probe_read(&iph, sizeof(iph), ip);

    put_ebpf_event_log(event, (const char *)&iph.saddr, sizeof(iph.saddr), TYPE_IPV4);
    put_ebpf_event_log(event, (const char *)&iph.daddr, sizeof(iph.daddr), TYPE_IPV4);

    char protocol[10];
    ebpf_memset(protocol, 0, sizeof(protocol));
	if (!ip_is_fragment(&iph)) {
		switch (iph.protocol) {
            case IPPROTO_UDP:
                ebpf_strncpy(protocol, "UDP", sizeof(protocol));
                break;
            case IPPROTO_TCP:
                ebpf_strncpy(protocol, "TCP", sizeof(protocol));
                break;
            default:
                ebpf_strncpy(protocol, "UNKNOWN", sizeof(protocol));
                break;
        }
    }
    put_ebpf_event_log(event, (const char *)protocol, sizeof(protocol), TYPE_STR);

    char app_name[30];
    ebpf_memset(app_name, 0, sizeof(app_name));
    bpf_get_current_comm(app_name, sizeof(app_name));
    put_ebpf_event_log(event, app_name, ebpf_strnlen(app_name, sizeof(app_name)), TYPE_STR);

	struct sec_path *sp = skb_sec_path(skb);
    if (sp) {
        // tunnel check
    }

    lsm_events.ringbuf_submit(event, 0);

    return 0;
}