// SPDX-License-Identifier: 2023
// Copyright Zhao Zhe (Alex)
// Firewall mod provide ingress firewall
// Multi functional firewall based on 
// allow access track and also allow dest
// monitoring at XDP layer and also track the forwarding
// of traffic within kernel
// 
// eBPF firewall based on default block all traffic design
//
// eBPF firewall module shall contain 
// [prefix]_ingress
// [prefix]_egress
// [prefix]_forwarding
//
// and configuration parameters map shall follow definition:
// 
//
#include <uapi/linux/bpf.h> 
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/sctp.h>
#include <linux/icmp.h>

#include <ebpf/ebpf_str.h>
#include <ebpf/ebpf_zone_firewall.h>

BPF_PERF_OUTPUT(pkts);

// Ingress associate with each interface id
BPF_ARRAY(tcp_ingress_ports, struct zone_port_rule, 10);
BPF_ARRAY(udp_ingress_ports, struct zone_port_rule, 10);
BPF_ARRAY(icmp_ingress_ports, struct zone_port_rule, 10);
BPF_ARRAY(sctp_ingress_ports, struct zone_port_rule, 10);

// Egress associate with each interface id
BPF_ARRAY(tcp_egress_ports, struct zone_port_rule, 10);
BPF_ARRAY(udp_egress_ports, struct zone_port_rule, 10);
BPF_ARRAY(icmp_egress_ports, struct zone_port_rule, 10);
BPF_ARRAY(sctp_egress_ports, struct zone_port_rule, 10);

// LPM based IP sets to control the forwarding 


/// @brief Firewall ingress 
/// @param ctx 
/// @return 
int firewall_ingress(struct xdp_md *ctx) {
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;
    u32 intf = ctx->ingress_ifindex;
    u32 len = data_end - data;

    struct ethhdr *eth = data;
    
    long *value;
    uint16_t h_proto;
    uint64_t nh_off = 0;

    nh_off = sizeof(*eth);

    // Not a Ethernet packet
    if (data + nh_off  > data_end)
        return XDP_DROP;

    h_proto = ntohs(eth->h_proto);

    if (h_proto == ETH_P_8021Q || h_proto == ETH_P_8021AD) {
        struct vlan_hdr *vhdr;

        vhdr = data + nh_off;
        nh_off += sizeof(struct vlan_hdr);
        if (data + nh_off > data_end)
            return XDP_DROP;

        h_proto = ntohs(vhdr->h_vlan_encapsulated_proto);
    }

    // QinQ
    if (h_proto == ETH_P_8021Q || h_proto == ETH_P_8021AD) {
        struct vlan_hdr *vhdr;

        vhdr = data + nh_off;
        nh_off += sizeof(struct vlan_hdr);
        if (data + nh_off > data_end)
            return XDP_DROP;
        
        h_proto = ntohs(vhdr->h_vlan_encapsulated_proto);
    }
    // L2 layer firewall 

    if (h_proto == ETH_P_IP) {
        struct iphdr *iph = data + nh_off;
        
        nh_off += sizeof(struct iphdr);
        if (data + nh_off > data_end)
            return XDP_DROP;
        
        h_proto = iph->protocol;
    
    } else if (h_proto == ETH_P_IPV6) {
        struct ipv6hdr *ip6h = data + nh_off;

        nh_off += sizeof(struct ipv6hdr);
        if (data + nh_off > data_end)
            return XDP_DROP;

        h_proto = ip6h->nexthdr;
        // search until TCP/UDP
    } else if (h_proto == ETH_P_ARP || h_proto == ETH_P_RARP) {
        // ARP and RARP direct pass  
        return XDP_PASS;
    } else {
        // All other no IP protocol direct drop
        return XDP_DROP;
    }

    // L3 layer firewall 
    u32 payload_len = data_end - data - nh_off;

    void *ports = NULL;
    u16 dst_port = 0;
    switch (h_proto) { 
        case IPPROTO_UDP: {
            struct udphdr *hdr = data + nh_off;

            nh_off += sizeof(struct udphdr);
            if (data + nh_off > data_end)
                return XDP_DROP;

            dst_port = ntohs(hdr->dest);
            ports = udp_ingress_ports.lookup(&intf);
            break;
        }
        case IPPROTO_TCP: { 
            struct tcphdr *hdr = data + nh_off;

            nh_off += sizeof(struct tcphdr);
            if (data + nh_off > data_end)
                return XDP_DROP;

            dst_port = ntohs(hdr->dest);
            ports = tcp_ingress_ports.lookup(&intf);
            break;
        }
        case IPPROTO_ICMP: {
            struct icmphdr *hdr = data + nh_off;

            nh_off += sizeof(struct icmphdr);
            if (data + nh_off > data_end)
                return XDP_DROP;

            dst_port = hdr->type;
            dst_port = dst_port << 8 | hdr->code;
            ports = icmp_ingress_ports.lookup(&intf);
            break;
        }
        case IPPROTO_SCTP: {
            struct sctphdr *hdr = data + nh_off;

            nh_off += sizeof(struct sctphdr);
            if (data + nh_off > data_end) 
                return XDP_DROP;

            dst_port = ntohs(hdr->dest);
            ports = sctp_ingress_ports.lookup(&intf);
            break;
        }
        default:
            break;
    }

    if (ports) {
        barrier_var(dst_port);
        if (dst_port >= 1024) {
            return XDP_PASS;
        }

        struct zone_port_rule *rule_set = (struct zone_port_rule *)ports;
        if (rule_set->ports[dst_port].allow) {
            return XDP_PASS;
        } else {
            return XDP_DROP;
        }
    }

    // Interface not attached with zone firewall
    // Receive the packets to IP stack 

    return XDP_PASS;
}

/// @brief Firewall forwarding  
/// @param ctx 
/// @return 
int firewall_forwarding(struct xdp_md *ctx) {
    return XDP_PASS;
}


/// @brief Firewall egress   
/// @return 
int firewall_egress(struct xdp_md *ctx) {
    return XDP_PASS;
}