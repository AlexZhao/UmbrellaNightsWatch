import ctypes

class file_info(ctypes.Structure):
    _fields_ = [("name", ctypes.c_char * 64)]

def convert_str_to_fileinfo(str):
    file = file_info()
    file.name = bytes(str[:63], 'ascii')
    return (True, file)