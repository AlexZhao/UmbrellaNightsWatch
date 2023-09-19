# Apache 2.0
# Copyright 2023 Zhao Zhe(Alex)
#

import ctypes as ct

class zone_recording_rule(ct.Structure):
    _fields_ = [("level", ct.c_byte)]

class zone_firewall_rule(ct.Structure):
    _fields_ = [("allow", ct.c_bool)]


class zone_port_rule(ct.Structure):
    _fields_ = [("enabled", ct.c_bool),
                ("ports", zone_firewall_rule * 1024),
                ("recs", zone_recording_rule * 1024)]

class ZoneFirewall:
    def __init__(self):
        """
        Zone based firewall interface 
        """

    @classmethod
    def generate_port_rule(cls, zone_firewall_config):
        zone_config = zone_port_rule()
        zone_config.enabled = True
        for i in range(0,1024):
            zone_config.ports[i] = zone_firewall_rule()
            zone_config.recs[i] = zone_recording_rule()

        for port_num, config in zone_firewall_config.items():
            port_n = int(port_num)
            if port_n < 1024:
                zone_config.ports[port_n].allow = True
        
        return zone_config