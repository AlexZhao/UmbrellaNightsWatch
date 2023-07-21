import ctypes

class task_info(ctypes.Structure):
    _fields_ = [("comm", ctypes.c_char * 16)]

def convert_str_to_taskinfo(str):
    task = task_info()
    task.comm = bytes(str[:15], 'ascii')
    return (True, task)