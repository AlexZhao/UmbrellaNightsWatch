import ctypes

def convert_str_to_int(str):
    try:
        val = int(str)
        return (True, ctypes.c_int(val))
    except:
        return (False, None)