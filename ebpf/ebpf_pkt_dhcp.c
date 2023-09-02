// SPDX-License-Identifier: 2023
// Copyright Zhao Zhe (Alex)
//
// eBPF based ARP/ND/DHCP packets filter to understand
// network access target without gateway
// SKB based DHCP packet filter
// attached to 
//   external ports -> optional
//   lo -> mandatory
//   configed ports -> optional
//


BPF_PERF_OUTPUT(dhcp_pkts);

BPF_PERF_OUTPUT(arp_nd_pkts);


#define PKT_DHCP_REQUEST  3
#define PKT_DHCP_RESPONSE 4
#define PKT_ARP_REQ       5
#define PKT_ARP_RES       6

/// @brief  Perf Bootstrap packets filter out 
/// @param ctx 
/// @return 
int xdp_bootstrap_filter(struct xdp_md *ctx) {

}