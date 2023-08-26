// SPDX-License-Identifier: 2023
// Copyright Alex Zhao
//
// eBPF based DNS packets filter to understand
// network access target without gateway
// SKB based DNS packet filter
// attached to 
//   external ports -> optional
//   lo -> mandatory
//   configed ports -> optional
//
// use to identify back to application req/res, not only host level
//
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>

BPF_PERF_OUTPUT(pkts);


#define PKT_DNS_REQUEST 1
#define PKT_DNS_RESPONSE 2

struct metadata {
    u64 timestamp;
    u32 pkt_len;
    u16 pkt_type;
    u16 pkt_offset;
};

/// @brief  Perf DNS packet filter out 
/// @param ctx 
/// @return 
int xdp_dns_filter(struct xdp_md *ctx) {
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;

    struct ethhdr *eth = data;
    
    long *value;
    uint16_t h_proto;
    uint64_t nh_off = 0;
    uint32_t index;

    nh_off = sizeof(*eth);

    // Not a Ethernet packet
    if (data + nh_off  > data_end)
        return XDP_PASS;

    h_proto = eth->h_proto;

    if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
        struct vlan_hdr *vhdr;

        vhdr = data + nh_off;
        nh_off += sizeof(struct vlan_hdr);
        if (data + nh_off > data_end)
            return XDP_PASS;

        h_proto = vhdr->h_vlan_encapsulated_proto;
    }

    // QinQ
    if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
        struct vlan_hdr *vhdr;

        vhdr = data + nh_off;
        nh_off += sizeof(struct vlan_hdr);
        if (data + nh_off > data_end)
            return XDP_PASS;
        
        h_proto = vhdr->h_vlan_encapsulated_proto;
    }

    if (h_proto == htons(ETH_P_IP)) {
        struct iphdr *iph = data + nh_off;
        
        nh_off += sizeof(struct iphdr);
        if (data + nh_off > data_end)
            return XDP_PASS;
        
        h_proto = iph->protocol;
    
    } else if (h_proto == htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6h = data + nh_off;

        nh_off += sizeof(struct ipv6hdr);
        if (data + nh_off > data_end)
            return XDP_PASS;

        // Warning: this is not full impl, ip6h next header may have next_hop which provide segment routing
        // this is a short path no other IPv6 ext header in the packet 
        h_proto = ip6h->nexthdr;
    }

    // Filter Out UDP packet and 
    if (h_proto == IPPROTO_UDP) {
        struct udphdr *udph = data + nh_off;

        nh_off += sizeof(struct udphdr);
        if (data + nh_off > data_end)
            return XDP_PASS;

        // DNS filter out
        if (udph->source == htons(53)) {
            // DNS response
            struct metadata meta;
            meta.timestamp = bpf_ktime_get_tai_ns();
            meta.pkt_len = (u32)(data_end - data);
            meta.pkt_type = PKT_DNS_RESPONSE;
            meta.pkt_offset = nh_off;
            pkts.perf_submit_skb(ctx, meta.pkt_len, &meta, sizeof(meta));
        }

        if (udph->dest == htons(53)) {
            // DNS request
            struct metadata meta;
            meta.timestamp = bpf_ktime_get_tai_ns();
            meta.pkt_len = (u32)(data_end - data);
            meta.pkt_type = PKT_DNS_REQUEST;
            meta.pkt_offset = nh_off;
            pkts.perf_submit_skb(ctx, meta.pkt_len, &meta, sizeof(meta));
        }
    }

    return XDP_PASS;
}