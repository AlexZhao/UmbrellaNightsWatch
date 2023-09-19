import ctypes

def convert_str_to_netlink_proto(str):
    match str:
        case "route": 
            return (True, ctypes.c_int32(0))
        case "unused":
            return (True, ctypes.c_int32(1))
        case "usersock":
            return (True, ctypes.c_int32(2))
        case "firewall":
            return (True, ctypes.c_int32(3))
        case "sock_diag":
            return (True, ctypes.c_int32(4))
        case "nflog":
            return (True, ctypes.c_int32(5))
        case "xfrm":
            return (True, ctypes.c_int32(6))
        case "selinux":
            return (True, ctypes.c_int32(7))
        case "iscsi":
            return (True, ctypes.c_int32(8))
        case "audit":
            return (True, ctypes.c_int32(9))
        case "fib_lookup":
            return (True, ctypes.c_int32(10))
        case "connector":
            return (True, ctypes.c_int32(11))
        case "netfilter":
            return (True, ctypes.c_int32(12))
        case "ip6_fw":
            return (True, ctypes.c_int32(13))
        case "dnrtmsg":
            return (True, ctypes.c_int32(14))
        case "kobject_uevent":
            return (True, ctypes.c_int32(15))
        case "generic":
            return (True, ctypes.c_int32(16))
        case "scsitransport":
            return (True, ctypes.c_int32(18))
        case "ecryptfs":
            return (True, ctypes.c_int32(19))
        case "rdma":
            return (True, ctypes.c_int32(20))
        case "crypto":
            return (True, ctypes.c_int32(21))
        case "smc":
            return (True, ctypes.c_int32(22))
        case _:
            return (False, ctypes.c_int32(-1))        

