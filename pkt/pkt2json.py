#!/usr/bin/python
# Apache License V2
# Copyright Alex Zhao
# Packet parse into Json
#
# enum packet type supported by pkt2json 
import json
import ctypes as ct

from dnslib import DNSRecord
from dnslib.bimap import Bimap, BimapError
from dnslib import QTYPE, CLASS

ETH_P_IP = 0x0800
ETH_P_IP6 = 0x86DD

# ETH header of the packet
class eth_header(ct.BigEndianStructure):
    _fields_ = [("h_dest", ct.c_uint8 * 6),
                ("h_source", ct.c_uint8 * 6),
                ("h_proto", ct.c_uint16)]

# IPv4 header of the packet
class ip4_header(ct.BigEndianStructure):
    _fields_ = [("version", ct.c_uint8),
                ("tos", ct.c_uint8),
                ("tot_len", ct.c_uint16),
                ("id", ct.c_uint16),
                ("frag_off", ct.c_uint16),
                ("ttl", ct.c_uint8),
                ("protocol", ct.c_uint8),
                ("check", ct.c_uint16),
                ("s_addr", ct.c_uint32),
                ("d_addr", ct.c_uint32)]

class ip4_addr(ct.Structure):
    _fields_ = [("addr", ct.c_uint8 * 4)]

# IPv6 header of the packet
class ip6_header(ct.BigEndianStructure):
    _fields_ = [("version", ct.c_uint8),
                ("flow_lbl", ct.c_uint8 * 3),
                ("payload_len", ct.c_uint16),
                ("next_hdr", ct.c_uint8),
                ("hop_limit", ct.c_uint8),
                ("saddr", ct.c_uint32 * 4),
                ("daddr", ct.c_uint32 * 4)]

class ip6_addr(ct.Structure):
    _fields_ = [("addr", ct.c_uint16 * 8)]

class PKT2JSON:
    def __init__(self):
        """
        Packet parse to JSON 
        """

    @classmethod
    def parse_ip(cls, pkt_offset, packet):
        """
        Parse the IP header from raw data
        """
        off = 0
        eth_h = ct.cast(packet, ct.POINTER(eth_header)).contents
        off = ct.sizeof(eth_header)

        mac_info = dict({})
        try:
            s_mac = bytes(eth_h.h_source)
            d_mac = bytes(eth_h.h_dest)
            mac_info["src"] = "%02x:%02x:%02x:%02x:%02x:%02x" % (s_mac[0], s_mac[1], s_mac[2], s_mac[3], s_mac[4], s_mac[5])
            mac_info["dst"] = "%02x:%02x:%02x:%02x:%02x:%02x" % (d_mac[0], d_mac[1], d_mac[2], d_mac[3], d_mac[4], d_mac[5])
        except BaseException as e:
            print(e)

        ip_info = dict({})

        match eth_h.h_proto:
            case 0x0800:
                ip_h = ct.cast(ct.byref(packet, off), ct.POINTER(ip4_header)).contents
                try:
                    s_addr = bytes(ct.c_uint32(ip_h.s_addr))
                    d_addr = bytes(ct.c_uint32(ip_h.d_addr))
                    ip_info["src"] = "{}.{}.{}.{}".format(s_addr[3], s_addr[2], s_addr[1], s_addr[0])
                    ip_info["dst"] = "{}.{}.{}.{}".format(d_addr[3], d_addr[2], d_addr[1], d_addr[0])
                except BaseException as e:
                    print(e)
                
            case 0x86DD:
                ip6_h = ct.cast(ct.byref(packet, off), ct.POINTER(ip6_header)).contents
                # TODO IPv6

        return mac_info, ip_info

    @classmethod
    def parse(cls, pkt_type, pkt_len, pkt_offset, packet):
        pkt_info = dict({})
        mac_info, ip_info = PKT2JSON.parse_ip(pkt_offset, packet)
        pkt_info["mac_header"] = mac_info
        pkt_info["ip_header"] = ip_info

        match pkt_type:
            case 1:  # DNS_REQUEST
                pkt_info["pkt_type"] = "dns_request"
                
                try:
                    dns_pkt = DNSRecord.parse(packet[pkt_offset:])
                    questions = []
                    for q in dns_pkt.questions:
                        questions.append(q.toZone()[1:])
                    rrs = []
                    for r in dns_pkt.rr:
                        rrs.append(r.toZone())
                    auths = []
                    for auth in dns_pkt.auth:
                        auths.append(auth.toZone())
                    ars = []
                    for ar in dns_pkt.ar:
                        ars.append(ar.toZone())

                    pkt_info["questions"] = questions
                    pkt_info["rrs"] = rrs
                    pkt_info["auths"] = auths
                    pkt_info["ars"] = ars
                except BaseException as e:
                    print(e)
                
                return pkt_info
            case 2: # DNS_RESPONSE
                pkt_info["pkt_type"] = "dns_response"

                try:
                    dns_pkt = DNSRecord.parse(packet[pkt_offset:])
                    questions = []
                    for q in dns_pkt.questions:
                        questions.append(q.toZone()[1:])
                    rrs = []
                    for r in dns_pkt.rr:
                        rrs.append(r.toZone())
                    auths = []
                    for auth in dns_pkt.auth:
                        auths.append(auth.toZone())
                    ars = []
                    for ar in dns_pkt.ar:
                        ars.append(ar.toZone())

                    pkt_info["questions"] = questions
                    pkt_info["rrs"] = rrs
                    pkt_info["auths"] = auths
                    pkt_info["ars"] = ars
                except BaseException as e:
                    print(e)
                
                return pkt_info
            case _:
                pkt_info["pkt_type"] = "unknown"

                return pkt_info
