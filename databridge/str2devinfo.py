import ctypes

class dev_info(ctypes.Structure):
    _fields_ = [("devname", ctypes.c_char * 32)]

def convert_str_to_devinfo(str):
    dev = dev_info()
    dev.devname = bytes(str, 'ascii')
    return (True, dev)