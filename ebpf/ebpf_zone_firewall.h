// SPDX-License-Identifier: 2023
// Copyright Zhao Zhe (Alex)
// Basic eBPF zone firewall data structure 
//
// Interface data structure for python and ebpf data exchange
// 
#ifndef EBPF_ZONE_FIREWALL
#define EBPF_ZONE_FIREWALL

#define ZONE_REC_DISABLED 0
#define ZONE_REC_HANDSHAKE 1
#define ZONE_REC_ALL 255

struct zone_recording_rule {
    u8 level;
};

struct zone_firewall_rule {
    bool allow;
};

struct zone_port_rule {
    bool enabled;    
    struct zone_firewall_rule ports[1024];          // Zone Controlling Firewall 
    struct zone_recording_rule recs[1024];          // Zone Controlling packet recording  
};

struct zone_tracking_links {

};

// Storage of the tracking links
struct zone_tracking_rec {
    struct zone_tracking_links trackings;           // Data buffer of the tracking links  
};

#endif