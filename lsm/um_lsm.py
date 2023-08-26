#!/usr/bin/python
# Apache License V2
# Copyright Alex Zhao
# Simplified version of Umbrella
#   MAC/LSM system security control
#
# Not able to be modified during runtime
from bcc import BPF
import threading
import time
import sys
import json
import os

import ctypes as ct

from datetime import datetime
from databridge.dispatcher import Dispatcher
import databridge

from multiprocessing import Process, Pipe;
from multiprocessing.connection import wait;

ebpf_shield = """
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/bpf.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/fdtable.h>

#include <net/sock.h>

BPF_RINGBUF_OUTPUT(lsm_events, 1 << 4);

#define MAXIMUM_LOOP 10

// BPF syscall only allow nw to configure to avoid security breach
// TODO: limit nw's progs/maps only can be modifed by nw
LSM_PROBE(bpf, int cmd, union bpf_attr *attr, unsigned int size) {
    int hold_shield = 0;
    
    switch (cmd) {
    case BPF_PROG_LOAD:
        {
            enum bpf_prog_type type; 
            if (bpf_probe_read_kernel(&type, sizeof(type), &attr->prog_type) == 0) {
                if (type == BPF_PROG_TYPE_LSM) {
                    hold_shield = 1;
                }
            }
        } 
        break;
    case BPF_MAP_LOOKUP_ELEM:
    case BPF_MAP_UPDATE_ELEM:
    case BPF_MAP_DELETE_ELEM:
    case BPF_MAP_GET_NEXT_KEY:
    case BPF_MAP_LOOKUP_AND_DELETE_ELEM:
        {
            // TODO check fowner is nw
            hold_shield = 1;
        }
        break;
    case BPF_MAP_LOOKUP_BATCH:
    case BPF_MAP_LOOKUP_AND_DELETE_BATCH:
    case BPF_MAP_UPDATE_BATCH:
    case BPF_MAP_DELETE_BATCH:
        {
            // TODO Check fowner
            hold_shield = 1;
        }
        break;
    default:
        break;
    }

    if (hold_shield) {
        struct task_struct *current_task = NULL;
        struct task_struct *parent_task = NULL;
        pid_t pid;

        current_task = (struct task_struct *)bpf_get_current_task();
        if (current_task == NULL) {
            return -EPERM;
        }
    
        #pragma clang loop unroll(full)
        for (int i = 0; i < MAXIMUM_LOOP; i++) {
            if (bpf_probe_read_kernel(&pid, sizeof(pid), &current_task->pid) == 0) {
                if (pid == RUNTIME_MON_PID) {
                    return 0;
                } else if (pid == 1) {
                    return -EPERM;
                }
            } else {
                return -EPERM;
            }

            if (bpf_probe_read_kernel(&parent_task, sizeof(parent_task), &current_task->real_parent) != 0) {
                return -EPERM;
            }
            current_task = parent_task;
        }

        return -EPERM;
    } else {
        return 0;
    }
}

#ifdef SHIELD_PERSISTENT
// nw avoid be traced by any
LSM_PROBE(ptrace_traceme, struct task_struct *parent) {
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent_task = NULL;
    pid_t pid;

    if (current_task == NULL) {
        return -EPERM;
    }

    #pragma clang loop unroll(full)
    for (int i = 0; i < MAXIMUM_LOOP; i++) {
        if (bpf_probe_read_kernel(&pid, sizeof(pid), &current_task->pid) == 0) {
            if (pid == RUNTIME_MON_PID) {
                return -EPERM;
            } else if (pid == 1) {
                return 0;
            }
        } else {
            return -EPERM;
        }
    
        if (bpf_probe_read_kernel(&parent_task, sizeof(parent_task), &current_task->real_parent) != 0) {
            return -EPERM;
        }
        current_task = parent_task;
    }
    
    return 0;
}

// nw avoid be traced by any
LSM_PROBE(ptrace_access_check, struct task_struct *child, unsigned int mode) {
    struct task_struct *current_task = child;
    struct task_struct *parent_task = NULL;
    pid_t pid;

    if (current_task == NULL) {
        return -EPERM;
    }

    #pragma clang look unroll(full)
    for (int i = 0; i < MAXIMUM_LOOP; i++) {
        if (bpf_probe_read_kernel(&pid, sizeof(pid), &current_task->pid) == 0) {
            if (pid == RUNTIME_MON_PID) {
                return -EPERM;
            } else if (pid == 1) {
                return 0;
            }
        } else {
            return -EPERM;
        }

        if (bpf_probe_read_kernel(&parent_task, sizeof(parent_task), &current_task->real_parent) != 0) {
            return -EPERM;
        }
        current_task = parent_task;
    }

    return 0;
}

// Silent nw daemon process, exceptional:
//    Netlink traffic     
LSM_PROBE(socket_connect, struct socket *sock, struct sockaddr *address, int addrlen) {
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent_task = NULL;
    pid_t pid;
    struct sock *sk = sock->sk;
    
    if (current_task == NULL) {
        return -EPERM;
    }

    #pragma clang loop unroll(full)
    for (int i = 0; i < MAXIMUM_LOOP; i++) {
        if (bpf_probe_read_kernel(&pid, sizeof(pid), &current_task->pid) == 0) {
            if (pid == RUNTIME_MON_PID) {
            
                if (sk->sk_family != AF_NETLINK)
                    return -EPERM;
                else
                    return 0;
            
            } else if (pid == 1) {
                return 0;
            }
        } else {
            return -EPERM;
        }
    
        if (bpf_probe_read_kernel(&parent_task, sizeof(parent_task), &current_task->real_parent) != 0) {
            return -EPERM;
        }
        current_task = parent_task;
    }
    
    return 0;
}

LSM_PROBE(socket_sendmsg, struct socket *sock, struct msghdr *msg, int size) {
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent_task = NULL;
    pid_t pid;
    socket_state state;
    struct sock *sk = sock->sk;
    
    if (current_task == NULL) {
        return -EPERM;
    }

    #pragma clang loop unroll(full)
    for (int i = 0; i < MAXIMUM_LOOP; i++) {
        if (bpf_probe_read_kernel(&pid, sizeof(pid), &current_task->pid) == 0) {
            if (pid == RUNTIME_MON_PID) {
                
                if (sk->sk_family == AF_NETLINK) 
                    return 0;

                bpf_probe_read_kernel(&state, sizeof(state), &sock->state);
                if (state != SS_CONNECTED)
                    return -EPERM;
                else
                    return 0;
            
            } else if (pid == 1) {
                return 0;
            }
        } else {
            return -EPERM;
        }
    
        if (bpf_probe_read_kernel(&parent_task, sizeof(parent_task), &current_task->real_parent) != 0) {
            return -EPERM;
        }
        current_task = parent_task;
    }
    
    return 0;
}

// TODO: 
//     LSM_PROBE(task_kill, reject all signals the final sheild to protect NW be killed by any userspace process  
//     LSM_PROBE(sched,  reject all the operation can adjust NW to work in low priority and keep NW works as realtime process      

//#ifdef SHIELD_PERSISTENT
LSM_PROBE(task_kill, struct task_struct *p, struct kernel_siginfo *info, int sig, const struct cred *cred) {
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent_task = NULL;
    pid_t pid;

    #pragma clang look unroll(full)
    for (int i = 0; i < MAXIMUM_LOOP; i++) {
        if (bpf_probe_read_kernel(&pid, sizeof(pid), &current_task->pid) == 0) {
            if (pid == RUNTIME_MON_PID) {
                return 0;
            } else if (pid == 1) {
                break;
            }
        } else {
            return -EPERM;
        }

        if (bpf_probe_read_kernel(&parent_task, sizeof(parent_task), &current_task->real_parent) != 0) {
            return -EPERM;
        }
        current_task = parent_task;
    }

    current_task = p;
    parent_task = NULL;
    #pragma clang look unroll(full)
    for (int i = 0; i < MAXIMUM_LOOP; i++) {
        if (bpf_probe_read_kernel(&pid, sizeof(pid), &current_task->pid) == 0) {
            if (pid == RUNTIME_MON_PID) {
                return -EPERM;
            } else if (pid == 1) {
                return 0;
            }
        } else {
            return -EPERM;
        }

        if (bpf_probe_read_kernel(&parent_task, sizeof(parent_task), &current_task->real_parent) != 0) {
            return -EPERM;
        }
        current_task = parent_task;
    }

    return 0;
}
#endif
"""

MAXIMUM_EVENT_LEN = 32
MAXIMUM_EVENT = 6 + 1

class ebpf_event(ct.Structure):
    _fields_ = [("ebpf_event_section", ct.c_uint32),
                ("timestamp", ct.c_uint64),
                ("lsm_func", ct.c_byte * MAXIMUM_EVENT_LEN),
                ("sections", (ct.c_byte * MAXIMUM_EVENT_LEN) * MAXIMUM_EVENT)]


def convert_uint_to_ushort(ip):
    ip_section = ct.c_uint32(ip)
    first_ushort = ct.c_ushort(0)
    second_ushort = ct.c_ushort(0)
    
    first_ushort.value |= ((ip_section.value & 0x000000FF) << 8)
    first_ushort.value |= ((ip_section.value & 0x0000FF00) >> 8)
    
    second_ushort.value |= ((ip_section.value & 0x00FF0000) >> 8)
    second_ushort.value |= ((ip_section.value & 0xFF000000) >> 24)

    return first_ushort.value, second_ushort.value

def convert_bytes_to_str(bytes):
    try:
        match bytes[0]:
            case 0:  # TYPE_STR
                return ct.cast(ct.byref(bytes, 2), ct.c_char_p).value.decode("utf-8")
            case 1:  # TYPE_I16
                return str(ct.cast(ct.byref(bytes, 2), ct.POINTER(ct.c_short)).contents.value)
            case 2:  # TYPE_U16
                return str(ct.cast(ct.byref(bytes, 2), ct.POINTER(ct.c_ushort)).contents.value)
            case 3:  # TYPE_I32
                return str(ct.cast(ct.byref(bytes, 2), ct.POINTER(ct.c_int)).contents.value)
            case 4:  # TYPE_U32
                return str(ct.cast(ct.byref(bytes, 2), ct.POINTER(ct.c_uint32)).contents.value)
            case 5:  # TYPE_I64
                return str(ct.cast(ct.byref(bytes, 2), ct.POINTER(ct.c_int64)).contents.value)
            case 6:  # TYPE_U64
                return str(ct.cast(ct.byref(bytes, 2), ct.POINTER(ct.c_uint64)).contents.value)
            case 7: # TYPE_IPV4
                ip_1 = ct.cast(ct.byref(bytes, 2), ct.POINTER(ct.c_ubyte)).contents.value
                ip_2 = ct.cast(ct.byref(bytes, 3), ct.POINTER(ct.c_ubyte)).contents.value
                ip_3 = ct.cast(ct.byref(bytes, 4), ct.POINTER(ct.c_ubyte)).contents.value
                ip_4 = ct.cast(ct.byref(bytes, 5), ct.POINTER(ct.c_ubyte)).contents.value
                return "{}.{}.{}.{}".format(ip_1, ip_2, ip_3, ip_4)
            case 8: # TYPE_IPV6
                ip_4 = ct.cast(ct.byref(bytes, 14), ct.POINTER(ct.c_uint32)).contents.value
                ip_3 = ct.cast(ct.byref(bytes, 10), ct.POINTER(ct.c_uint32)).contents.value
                ip_2 = ct.cast(ct.byref(bytes, 6), ct.POINTER(ct.c_uint32)).contents.value
                ip_1 = ct.cast(ct.byref(bytes, 2), ct.POINTER(ct.c_uint32)).contents.value

                ip_s_1, ip_s_2 = convert_uint_to_ushort(ip_1)
                ip_s_3, ip_s_4 = convert_uint_to_ushort(ip_2)
                ip_s_5, ip_s_6 = convert_uint_to_ushort(ip_3)
                ip_s_7, ip_s_8 = convert_uint_to_ushort(ip_4)
                return "{}:{}:{}:{}:{}:{}:{}:{}".format(hex(ip_s_1)[2:], hex(ip_s_2)[2:], hex(ip_s_3)[2:], hex(ip_s_4)[2:], hex(ip_s_5)[2:], hex(ip_s_6)[2:], hex(ip_s_7)[2:], hex(ip_s_8)[2:])
            case _: 
                return "Unknown"
    except BaseException as e:
        return "ConvertFailed {}".format(e)

def convert_ebpf_event_to_str(ebpf_name, ebpf_event):
    try:
        ts = datetime.fromtimestamp(ebpf_event.timestamp / 1000000000)
        timestamp = "{}.{}".format(ts.strftime('%Y-%m-%d %H:%M:%S'), str(int(ebpf_event.timestamp % 1000000000)).zfill(9))
        func_name = ct.cast(ebpf_event.lsm_func, ct.c_char_p).value.decode("utf-8")

        try:
            content = "["
            for i in range(ebpf_event.ebpf_event_section):
                str_text = convert_bytes_to_str(ebpf_event.sections[i])
                content = content + " {}".format(str_text)
            content = content + " ]"
        except BaseException as e:
            print(e)
            content = content + " ]"

        return "[{}]:[{}]:[{}] -> {}".format(ebpf_name, func_name, timestamp, content)
    except:
        return "[{}] -> [Failed]".format(ebpf_name)

def log_of_lsm_daemon(ebpf_name, attached_ebpf, log_pipe, log_convert_fn=None):

    def log_str_gen(ctx, data, size):
        """
        Generate Log string for polling
        """
        try:
            log_str = "Unknown"
            if log_convert_fn:
                log_str = log_convert_fn(ctx, data, size)
            else:
                event = ct.cast(data, ct.POINTER(ebpf_event)).contents
                log_str = convert_ebpf_event_to_str(ebpf_name, event)
        except BaseException as e:
            log_str = "Convert exception {}".format(e)
            
        log = "{} -> event {}".format(ebpf_name, log_str)
        log_pipe.send(log)

    try:
        attached_ebpf["lsm_events"].open_ring_buffer(log_str_gen)    

        while True:
            attached_ebpf.ring_buffer_poll()
    except KeyboardInterrupt:
        sys.exit()

#
# command based on JSON request
# {
#    "cmd": ["list_all_items" | "config"],
#    "map": "",
#    "key": "value",
# }
#
#
def lsm_daemon(con_pipe, child_log_pipe, ebpf_name, ebpf_config, log_convert_fn=None):
    """
    LSM Daemon Process
    """
    if "ebpf" in ebpf_config:
        print("Equipped LSM {}:{}  {}".format(ebpf_name, os.getpid(), ebpf_config["ebpf"]))
    else:
        print("Not existed ebpf lsm for {}".format(ebpf_name))
        return

    try:
        if ebpf_config["ebpf"] == "ebpf_shield":
            """
            Loading ebpf shield
            """
            
            enable_persistent = False
            if ebpf_config["persist_shield"]:
                enable_persistent = ebpf_config["persist_shield"]
            try:
                append_str = "#define RUNTIME_MON_PID {}\n".format(ebpf_config["runtime_mon_pid"])

                persistent_str = ""                
                if enable_persistent:
                    persistent_str = "#define SHIELD_PERSISTENT 1\n"
                
                ebpf_shield_text = append_str + persistent_str + ebpf_shield
                attached_bpf= BPF(text=ebpf_shield_text)
            except Exception as e:
                print("eBPF without proper RUNTIME_MON_PID Configured  ", e)
                sys.exit()
        else:
            attached_bpf = BPF(src_file=ebpf_config["ebpf"])
    except BaseException as e:
        error_msg = "{}".format(e)
        print("failed to load ebpf {} with config {}, error {}".format(ebpf_name, ebpf_config, error_msg))
        con_pipe.send('''
        {
            "initialization" : "failed",
            "error_msg": "%s"
        }
        ''' % (error_msg))
        return

    if "config_maps" in ebpf_config:
        for config_map in ebpf_config["config_maps"]:
            if attached_bpf[config_map] is None:
                print("Not aligned config map {} in config file, but not in eBPF".format(config_map))

    lsm_log_th = threading.Thread(name="lsm_log.{}".format(ebpf_name), target=log_of_lsm_daemon, args=(ebpf_name, attached_bpf, child_log_pipe, log_convert_fn, ))
    lsm_log_th.start()

    data_dispatcher = Dispatcher()

    config_sets = dict({})
    if "config_sets" in ebpf_config:
        for config_set_name, config_set in ebpf_config["config_sets"].items():
            config_sets[config_set_name] = config_set

    # Initialize Configuration with predefined configs
    if "configs" in ebpf_config:
        for config_map_name, configs in ebpf_config["configs"].items():
            print("Initial Configuration for %s" % config_map_name)
            if "config_pairs" in configs:
                if isinstance(configs["config_pairs"], str):
                    if configs["config_pairs"] in config_sets:
                        for key, val in config_sets[configs["config_pairs"]].items():
                            if "key_convert" in configs:
                                key = data_dispatcher.convert(configs["key_convert"], key)
                            if "val_convert" in configs:
                                if configs["val_convert"] != "str2mapfd":
                                    val = data_dispatcher.convert(configs["val_convert"], val)
                                else:
                                    val = bytes(val, 'ascii')
                                    fdmap = attached_bpf.get_table(val)
                                    val = ct.c_int(fdmap.get_fd())
                            attached_bpf[config_map_name][key] = val
                    else:
                        print("Not able to find pre config set %" % configs["config_pairs"])
                else:
                    for key, val in configs["config_pairs"].items():
                        if "key_convert" in configs:
                            key = data_dispatcher.convert(configs["key_convert"], key)
                        if "val_convert" in configs:
                            if configs["val_convert"] != "str2mapfd":
                                val = data_dispatcher.convert(configs["val_convert"], val)
                            else:
                                val = bytes(val, 'ascii')
                                fdmap = attached_bpf.get_table(val)
                                val = ct.c_int(fdmap.get_fd())

                        attached_bpf[config_map_name][key] = val

    con_pipe.send('''
    {
        "initialization" : "finished"
    }
    ''')

    try:
        while True:
            cmd = con_pipe.recv()
            cmd_json = json.loads(cmd)

            try:
                match cmd_json["cmd"]:
                    case "list_all_items":
                        result = dict({"tables": [], "lsms": []})
                        for tn in attached_bpf:
                            result["tables"].append(tn)
                        for fn in attached_bpf.lsm_fds.keys():
                            result["lsms"].append(fn.decode('utf-8'))
                        con_pipe.send(json.dumps(result))
                    case "update_config":
                        print(cmd_json)
                        if "map" in cmd_json:
                            config_map = cmd_json["map"]
                            key = cmd_json["key"]
                            value = cmd_json["value"]
                            if cmd_json["key_convert"] != "None":
                                key = data_dispatcher.convert(cmd_json["key_convert"], cmd_json["key"])
                            if cmd_json["val_convert"] != "None" and cmd_json["val_convert"] != "str2mapfd":
                                value = data_dispatcher.convert(cmd_json["val_convert"], cmd_json["value"])

                            if cmd_json["val_convert"] == "str2mapfd":
                                value = bytes(value, 'ascii')
                                fdmap = attached_bpf.get_table(value)
                                value = ct.c_int(fdmap.get_fd())

                            print("Try to config {} {} {}".format(config_map, key, value))

                            attached_bpf[config_map][key] = value

                            con_pipe.send('''
                            {
                                "cmd_execute_result": "success",
                            }
                            ''')
                        else:
                            con_pipe.send('''
                            {
                                "cmd_execute_result": "failed",
                                "error": "target map not existed"
                            }
                            ''')
                    case "delete_config":
                        print(cmd_json)
                        con_pipe.send('''
                        {
                            "cmd_execute_result": "success",
                        }
                        ''')
                    case "exit":
                        print(ebpf_name, "Received command exit, it should be initiated by reload")
                        con_pipe.send('''
                        {
                            "cmd_execute_result": "sucess"
                        }
                        ''')
                        return
                    case _:
                        con_pipe.send("{'cmd_execute_result': 'unknown command'}")
            except:
                con_pipe.send('''
                {
                    "cmd_execute_result": "failed",
                    "error": "update command not correct format %s"
                }
                ''' % (cmd_json))
                print("Not able to process {}".format(cmd_json))
    except KeyboardInterrupt:
        sys.exit()
    
class eBPFLSMDaemon:
    def __init__(self, ebpf_name, ebpf_config):
        """
        eBPF LSM Daemon process
        """
        log_pipe, child_log_pipe = Pipe()
        parent_pipe, child_pipe = Pipe()
        self.con_pipe = parent_pipe
        self.log_pipe = log_pipe
        self.daemon_proc = Process(target=lsm_daemon, name=ebpf_name, args=(child_pipe, child_log_pipe, ebpf_name, ebpf_config, ))
        self.active = False
        self.ebpf_name = ebpf_name

    def __exit__(self):
        print("Exit [{}], cleanup environment".format(self.ebpf_name))
        self.daemon_proc.kill()
        self.daemon_proc.close()

    def start(self):
        self.daemon_proc.start()
        initialization_status = self.con_pipe.recv()
        status = json.loads(initialization_status)
        if status["initialization"] != "finished":
            self.active = False
        else:
            self.active = True

        return self.active

    def get_log_pipe(self):
        return self.log_pipe

    def list_all_items(self):
        cmd = '''
        { 
            "cmd":"list_all_items"
        }
        '''
        self.con_pipe.send(cmd)
        return self.con_pipe.recv()

    def update_lsm_config(self, map_name, key, value, key_convert, val_convert):
        cmd = """
        {
            "cmd":"update_config",
            "map":"%s",
            "key":"%s",
            "value":"%s",
            "key_convert":"%s",
            "val_convert":"%s"
        }
        """ % (map_name, key, value, key_convert, val_convert)
        self.con_pipe.send(cmd)
        return self.con_pipe.recv()

    def delete_lsm_config(self, map_name, key, value, key_convert, val_convert):
        cmd = """
        {
            "cmd":"delete_config",
            "map":"%s",
            "key":"%s",
            "value":"%s",
            "key_convert":"%s",
            "val_convert":"%s"
        }
        """ % (map_name, key, value, key_convert, val_convert)
        self.con_pipe.send(cmd)
        return self.con_pipe.recv()

    def reload(self, ebpf_name, ebpf_config):
        """
        1. create new ebpf instance
        2. remove existed ebpf instance
        3. no break time of the LSM module
        """
        try:
            log_pipe, child_log_pipe = Pipe()
            parent_pipe, child_pipe = Pipe()
            reloaded_daemon_process = Process(target=lsm_daemon, name=ebpf_name, args=(child_pipe, child_log_pipe, ebpf_name, ebpf_config, ))
            reloaded_daemon_process.start()

            initialization_status = parent_pipe.recv()
            status = json.loads(initialization_status)
            if status["initialization"] != "finished":
                return None, {'reload_lsm': 'failed', "lsm": ebpf_name}
        except BaseException as e:
            """
            """
            return None, {'reload_lsm': 'failed', "lsm": ebpf_name}

        cmd = """
        {
            "cmd": "exit"
        }
        """
        self.con_pipe.send(cmd)
        self.daemon_proc.terminate()
        self.daemon_proc.join()
        self.con_pipe.close()
        self.log_pipe.close()

        self.con_pipe = parent_pipe
        self.log_pipe = log_pipe
        self.daemon_proc = reloaded_daemon_process

        return log_pipe, {'reload_lsm' : 'success', 'lsm': ebpf_name}

class eBPFLSMLog:
    def __init__(self, ebpf_name, ebpf_log):
        self.log_name = ebpf_name
        self.config = ebpf_log
        self.log_file = None
        self.flush_threshold = 100
        self.flush_cnt = self.flush_threshold

        if "file" in ebpf_log:
            try:
                self.log_file = open(ebpf_log["file"], "a")
            except BaseException as e:
                print("Failed to open ebpf lsm log for {}  {}".format(ebpf_name, ebpf_log))
                self.log_file = None
        
        if "flush_threshold" in ebpf_log:
            try:
                self.flush_threshold = ebpf_log["flush_threshold"]
                self.flush_cnt = self.flush_threshold
            except BaseException as e:
                print("Wrong configuration of log flush threshold")
    
    def __exit__(self):
        self.log_file.close()

    def log(self, log_str):
        if self.log_file:
            self.log_file.write(log_str)
            self.log_file.write("\n")  
            self.flush_cnt = self.flush_cnt - 1
            if self.flush_cnt <= 0:
                self.log_file.flush()
                self.flush_cnt = self.flush_threshold

class UmbrellaLSM:
    def __init__(self, ebpf_files, operations=None):
        """
        Initiate of UmbrellaLSM userspace 
        """
        self.ebpf_daemons = dict({})
        self.ebpf_lsm_logs = dict({})
        self.operations = operations
        self.analyst = None

        log_reload_trigger, log_pipe = Pipe()
        self.log_trigger_pipe = log_reload_trigger

        for ebpf_name, ebpf_config in ebpf_files.items():
            self.execute_setup_operation(ebpf_config)
            try:
                self.ebpf_daemons[ebpf_name] = eBPFLSMDaemon(ebpf_name, ebpf_config)
                if "log" in ebpf_config:
                    ebpf_log = eBPFLSMLog(ebpf_name, ebpf_config["log"])                    
                    self.ebpf_lsm_logs[ebpf_name] = ebpf_log
            except:
                print("Failed to load {}", ebpf_name)

        self.log_monitor_pipes = []
        self.log_monitor_pipes.append(log_pipe)
        for ebpf_name, ebpf_daemon in self.ebpf_daemons.items():
            self.log_monitor_pipes.append(ebpf_daemon.get_log_pipe())


    def execute_setup_operation(self, ebpf_config):
        if self.operations is None:
            return
        
        config_sets = dict({})
        if "config_sets" in ebpf_config:
            for config_name, configs in ebpf_config["config_sets"].items():
                config_sets[config_name] = configs

        if "operation" in ebpf_config:
            if "setup" in ebpf_config["operation"]:
                for setup in ebpf_config["operation"]["setup"]:
                    for op_name, op_config in setup.items():
                        for op, param in op_config.items():
                            if isinstance(param, str):
                                if param in config_sets:
                                    self.operations.execute_operation(op_name, op, config_sets[param])
                                else:
                                    self.operations.execute_operation(op_name, op, param)
                            else:
                                self.operations.execute_operation(op_name, op, param)

    def set_analyst(self, analyst):
        self.analyst = analyst

    def set_nw_operations(self, operations):
        self.operations = operations

    def add_ebpf_lsm(self, new_lsm, ebpf_lsm_config):
        """
        Add eBPF LSM
        """
        if new_lsm not in self.ebpf_daemons:
            self.execute_setup_operation(ebpf_lsm_config)
            new_ebpf_lsm = eBPFLSMDaemon(new_lsm, ebpf_lsm_config)
            self.ebpf_daemons[new_lsm] = new_ebpf_lsm
            if self.ebpf_daemons[new_lsm].start() == False:
                self.ebpf_daemons.pop(new_lsm)
                return { 'add_lsm': 'failed', "lsm": new_lsm }

            
            if "log" in ebpf_lsm_config:
                ebpf_log = eBPFLSMLog(new_lsm, ebpf_lsm_config["log"])                    
                self.ebpf_lsm_logs[new_lsm] = ebpf_log
            
            self.log_monitor_pipes.append(new_ebpf_lsm.get_log_pipe())
            self.reload_log_pipe()
            return { 'add_lsm': 'success', "lsm": new_lsm }
        else:
            return { "add_lsm": "failed", "already_existed": new_lsm}

    def reload_log_pipe(self):
        self.log_trigger_pipe.send("Refresh log monitor")

    def reload_ebpf_lsm(self, reload_lsm, ebpf_lsm_config):
        """
        Reload already loaded eBPF LSM, runtime update
        """
        if reload_lsm in self.ebpf_daemons:
            log_pipe, res = self.ebpf_daemons[reload_lsm].reload(reload_lsm, ebpf_lsm_config)
            if log_pipe != None:
                if "log" in ebpf_lsm_config:
                    ebpf_log = eBPFLSMLog(reload_lsm, ebpf_lsm_config["log"])                    
                    self.ebpf_lsm_logs[reload_lsm] = ebpf_log

                self.log_monitor_pipes.append(log_pipe)
                self.reload_log_pipe()
                return res
            else:
                return res
        else:
            return {'reload_lsm': "failed", "not_existed": reload_lsm}

    def log_analysis_loop(self):
        try:
            while self.log_monitor_pipes:
                for pipe in wait(self.log_monitor_pipes):
                    try:
                        event_item = pipe.recv()                    
                        log_str = str(event_item)
                        lsm = log_str[:log_str.find("->")].strip()
                        if lsm not in self.ebpf_lsm_logs:
                            print(log_str)
                        else:
                            """
                            lsm specific log processing
                            """
                            self.ebpf_lsm_logs[lsm].log(log_str)

                    except BaseException as e:
                        self.log_monitor_pipes.remove(pipe)
        except KeyboardInterrupt:
            sys.exit()

    def start_all(self):
        """
        Start all eBPF LSM, parallel loading
        Seems like fake concurrent coroutines
        """
        for ebpf_name, ebpf_lsm in self.ebpf_daemons.items():
            ebpf_lsm.start()

        self.um_lsm_log_th = threading.Thread(name="um_lsm_log", target=self.log_analysis_loop)
        self.um_lsm_log_th.start()

    def start(self, ebpf_name):
        """
        Start eBPF 
        """
        if ebpf_name in self.ebpf_daemons:
            self.ebpf_daemon[ebpf_name].start()        


    def list_all(self):
        """
        List all LSM mods
        """
        result = []
        for ebpf_name, ebpf_lsm in self.ebpf_daemons.items():
            result.append(ebpf_name)
        
        return result
    
    def list_details_of_ebpf(self, ebpf_name):
        """
        List all the details of equipped LSM
        """
        if ebpf_name in self.ebpf_daemons:
            return self.ebpf_daemons[ebpf_name].list_all_items()
        else:
            return "{}"
        
    def update_lsm_config(self, ebpf_name, map_name, key, value, key_convert, value_convert):
        """
        Config eBPF map with key, value
        """
        if ebpf_name in self.ebpf_daemons:
            try:
                return self.ebpf_daemons[ebpf_name].update_lsm_config(map_name, key, value, key_convert, value_convert)
            except:
                return {"{}".format(ebpf_name):"config_failed on map {}".format(map_name), "{}".format(key):"{}".format(value) }
        else:
            return {}
        
    def delete_lsm_config(self, ebpf_name, map_name, key, value, key_convert, value_convert):
        """
        Delete eBPF map with key, value
        """
        if ebpf_name in self.ebpf_daemons:
            try:
                return self.ebpf_daemons[ebpf_name].delete_lsm_config(map_name, key, value, key_convert, value_convert)
            except:
                return {"{}".format(ebpf_name):"config_failed on map {}".format(map_name), "{}".format(key):"{}".format(value)}
        else:
            return {}
