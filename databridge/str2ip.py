# str to key_v4, key_v6 structure for basic ebpf_lsm
import unittest

import ctypes

class sockaddr_in(ctypes.Structure):
    _fields_ = [("sa_family", ctypes.c_ushort),  # sin_family
                ("sin_port", ctypes.c_ushort),
                ("sin_addr", ctypes.c_ubyte * 4),
                ("__pad", ctypes.c_byte * 8)]    # struct sockaddr_in is 16 bytes

class key_v4(ctypes.Structure):
    _fields_ = [("prefix", ctypes.c_uint32),
                ("data", ctypes.c_uint32)]

class key_v6(ctypes.Structure):
    _fields_ = [("prefix", ctypes.c_uint32),
                ("data", ctypes.c_uint32 * 4)]
    

def convert_str_to_ip_key(ip_addr_with_suffix):
    ip_and_suffix = ip_addr_with_suffix.split("/")
    if len(ip_and_suffix) == 2:
        ip_addr = ip_and_suffix[0]
        subnet = ip_and_suffix[1]
    elif len(ip_and_suffix) == 1:
        ip_addr = ip_and_suffix[0]
        subnet = ""
    ips = ip_addr.split(".")
    
    if len(ips) == 4:
        if subnet == "":
            subnet = "32"

        try:
            prefix = int(subnet)
            if prefix < 0 or prefix > 32:
                return (False, None)
            
            data = ctypes.c_uint32(0)
            cnt = 0
            for ip in ips:
                cnt = cnt + 1
                section = ctypes.c_uint32(int(ip))
                data.value |= (section.value << 24)
                if cnt < 4:
                    data.value >>= 8
            return (True, key_v4(prefix=prefix, data=data))
        
        except:
            return (False, None)

    else:
        if subnet == "":
            subnet = "128"
    
        try:
            prefix = int(subnet)
            if prefix < 0 or prefix > 128:
                return (False, None)

            ips = ip_addr.split("::")
            ipv6s = []

            # IPv6 Split
            if len(ips) == 2:
                # Shorts of IPv6, add 0 within addr
                # 8 ip sections
                ips1 = ips[0].split(":")
                ips2 = ips[1].split(":")
                if len(ips1) == 0:
                    ips1.append(ips[0])
                if len(ips2) == 0:
                    ips2.append(ips[1])
                
                existed_len = len(ips1) + len(ips2)
                pad_len = 8 - existed_len
                for ip in ips1:
                    if ip == '':
                        ipv6s.append('0')  # special handling to append '0' if ::1 if configured
                    else:
                        ipv6s.append(ip)
            
                for i in range(pad_len):
                    ipv6s.append("0")
            
                for ip in ips2:
                    ipv6s.append(ip)

            elif len(ips) == 0:
                ips = ip_addr.split(":")
                # Full IPv6 no shorts
                if len(ips) == 8:
                    ipv6s = ips
            else:
                return (False, None)

            if len(ipv6s) == 8:
                # convert str to key_v6
                iter = 0
                data = []
                d = ctypes.c_uint32(0)

                for ip in ipv6s:
                    if iter % 2 == 0:
                        d = ctypes.c_uint32(0)

                    d.value |= ctypes.c_uint32(int(ip, 16)).value
                    if iter % 2 == 0:
                        d.value <<= 16
                    iter = iter + 1

                    if iter % 2 == 0:
                        val = ctypes.c_uint32(0)
                        shift = 8

                        val.value |= ((d.value & 0x000000FF) << 24)
                        val.value |= ((d.value & 0x0000FF00) << 8)
                        val.value |= ((d.value & 0x00FF0000) >> 8)
                        val.value |= ((d.value & 0xFF000000) >> 24)

                        data.append(val)
                
                if len(data) == 4:
                    return (True, key_v6(prefix=prefix, data=(ctypes.c_uint32 * 4)(*data)))
                            
        except:
            return (False, None)

    return (False, None)

class TestStr2IP(unittest.TestCase):

    def test_ipv4_address(self):
        res, ipv4 = convert_str_to_ip_key("192.168.10.1")
        self.assertTrue(res)
        self.assertEqual(ipv4.prefix, 32)
        self.assertEqual(ipv4.data, 0x10aa8c0)

    def test_ipv4_subnet(self):
        res, netv4 = convert_str_to_ip_key("192.168.10.1/24")
        self.assertTrue(res)
        self.assertEqual(netv4.prefix, 24)
        self.assertEqual(netv4.data, 0x10aa8c0)

    def test_ipv6_address(self):
        res, ipv6 = convert_str_to_ip_key("3ffe::200:1")
        self.assertTrue(res)
        self.assertEqual(ipv6.prefix, 128)
        self.assertEqual(ipv6.data[0], 0x0000fe3f)
        self.assertEqual(ipv6.data[1], 0x00000000)
        self.assertEqual(ipv6.data[2], 0x00000000)
        self.assertEqual(ipv6.data[3], 0x01000002)

    def test_ipv6_subnet(self):
        res, netv6 = convert_str_to_ip_key("3ffe::200:1/96")
        self.assertTrue(res)
        self.assertEqual(netv6.prefix, 96)
        self.assertEqual(netv6.data[0], 0x0000fe3f)
        self.assertEqual(netv6.data[1], 0x00000000)
        self.assertEqual(netv6.data[2], 0x00000000)
        self.assertEqual(netv6.data[3], 0x01000002)
    
    def test_ipv6_local(self):
        res, netv6 = convert_str_to_ip_key("::1/112")
        self.assertTrue(res)
        self.assertEqual(netv6.prefix, 112)
        self.assertEqual(netv6.data[0], 0x00000000)
        self.assertEqual(netv6.data[1], 0x00000000)
        self.assertEqual(netv6.data[2], 0x00000000)
        self.assertEqual(netv6.data[3], 0x01000000)

if __name__ == '__main__':
    unittest.main()