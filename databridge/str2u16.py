import ctypes

def convert_str_to_u16(str):
    try:
        val = int(str)
        return (True, ctypes.c_ushort(val))
    except:
        return (False, None)