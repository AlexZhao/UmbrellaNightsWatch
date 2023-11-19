# Data Structure Converter Dispatcher

from databridge import str2ip
from databridge import str2taskinfo
from databridge import str2int
from databridge import str2u16
from databridge import str2kmod
from databridge import str2devinfo
from databridge import str2fileinfo
from databridge import str2netlink
from databridge import str2uid

class Dispatcher:
    def __init__(self):
        """
        Dispatcher to convert string to different type of stuctre used for eBPF c data structure
        based on converter names
        """

    def convert(self, key_convert, key):
        match key_convert:
            case "str2ip":
                res, data = str2ip.convert_str_to_ip_key(key)
                if res:
                    return data
                else:
                    return None
            case "str2taskinfo":
                res, data = str2taskinfo.convert_str_to_taskinfo(key)
                if res:
                    return data
                else:
                    return None
            case "str2int":
                res, data = str2int.convert_str_to_int(key)
                if res:
                    return data
                else:
                    return None
            case "str2u16":
                res, data = str2u16.convert_str_to_u16(key)
                if res:
                    return data
                else:
                    return None                
            case "str2kmod":
                res, data = str2kmod.convert_str_to_kmod(key)
                if res:
                    return data
                else:
                    return None
            case "str2devinfo":
                res, data = str2devinfo.convert_str_to_devinfo(key)
                if res:
                    return data
                else:
                    return None
            case "str2fileinfo":
                res, data = str2fileinfo.convert_str_to_fileinfo(key)
                if res:
                    return data
                else:
                    return None
            case "str2netlink":
                res, data = str2netlink.convert_str_to_netlink_proto(key)
                if res:
                    return data
                else:
                    return None
            case "str2uid":
                res, data = str2uid.convert_str_to_uid(key)
                if res:
                    return data
                else:
                    return None
            case _:
                return None

