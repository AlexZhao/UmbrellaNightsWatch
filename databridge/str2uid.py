# Convert Str username to uid 
import ctypes
import pwd

def convert_str_to_uid(str):
    try:
        pwd_entry = pwd.getpwnam(str)
        if pwd_entry:
            return (True, ctypes.c_uint32(pwd_entry.pw_uid))
        else:
            return (False, None)
    except:
        return (False, None)