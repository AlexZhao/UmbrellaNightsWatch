import ctypes

class kmod(ctypes.Structure):
    _fields_ = [("name", ctypes.c_char * 64)]

def convert_str_to_kmod(str):
    kmod_name = kmod()
    kmod_name.name = bytes(str, 'ascii')
    return (True, kmod_name)