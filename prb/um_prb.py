#!/usr/bin/python
#
# Apache License 2.0
# Copyright Zhao Zhe (Alex)
#
# NW Probes
#   tracepoint
#   raw_tracepoint
#   ...
# 
# It can be loaded and modify unload during NW running 
#
from bcc import BPF
import ctypes
import json
import os

import sys
import ctypes as ct
import socket

from multiprocessing import Process, Pipe
from multiprocessing.connection import wait

from analyst.provider import DataProvider

from datetime import datetime

import threading

class ebpf_prb_log(ct.Structure):
    _fields_ = [("ebpf_log_section", ct.c_int32),
                ("timestamp", ct.c_uint64),
                ("func", ct.c_byte * 32),
                ("sections", (ct.c_byte * 32) * 8)]

class sockaddr_in(ct.Structure):
    _fields_ = [("sa_family", ct.c_ushort),  # sin_family
                ("sin_port", ct.c_ushort),
                ("sin_addr", ct.c_ubyte * 4),
                ("__pad", ct.c_byte * 8)]    # struct sockaddr_in is 16 bytes

class sockaddr_in6(ct.Structure):
    _fields_ = [("sa_family", ct.c_ushort),
                ("sin6_port", ct.c_ushort),
                ("sin6_flow", ct.c_uint32),
                ("sin6_addr", ct.c_uint16 * 8),
                ("sin6_scope_id", ct.c_uint32)]

class sockaddr_un(ct.Structure):
    _fields_ = []

def from_sockaddr(sockaddr):
    addr = tuple(c for c in sockaddr.sin_addr)
    addr_str = '%d.%d.%d.%d' % addr 
    return "{}:{}".format(addr_str, socket.ntohs(sockaddr.sin_port))  

def from_sockaddr6(sockaddr):
    addr = tuple(socket.ntohs(c) for c in sockaddr.sin6_addr)
    addr_str = '%4x:%4x:%4x:%4x:%4x:%4x:%4x:%4x' % addr 
    return "{}:{}".format(addr_str, socket.ntohs(sockaddr.sin6_port))

def from_sockaddrun(sockaddr):
    return "TODO"

#define TYPE_STR 0
#define TYPE_I32 1
#define TYPE_U32 2
#define TYPE_I64 3
#define TYPE_U64 4
#define TYPE_SOCKADDR_4 5
#define TYPE_SOCKADDR_6 6
#define TYPE_SOCKADDR_UN 7

def convert_bytes_to_str(bytes):
    try:
        match bytes[0]:
            case 0:
                return ct.cast(ct.byref(bytes, 2), ct.c_char_p).value.decode("utf-8")
            case 1:
                return str(ct.cast(ct.byref(bytes, 2), ct.POINTER(ct.c_int)).contents.value)
            case 2:
                return str(ct.cast(ct.byref(bytes, 2), ct.POINTER(ct.c_uint32)).contents.value)
            case 3:
                return str(ct.cast(ct.byref(bytes, 2), ct.POINTER(ct.c_int64)).contents.value)
            case 4:
                return str(ct.cast(ct.byref(bytes, 2), ct.POINTER(ct.c_uint64)).contents.value)
            case 5:
                return from_sockaddr(ct.cast(ct.byref(bytes, 2), ct.POINTER(sockaddr_in)).contents)
            case 6:
                return from_sockaddr6(ct.cast(ct.byref(bytes, 2), ct.POINTER(sockaddr_in6)).contents)
            case 7:
                return "UnixSocket"
            case _: 
                return "Unknown"
    except BaseException as e:
        return "ConvertFailed {}".format(e)

# [prb_name]:[probe_func]:[timestamp] [app_name]:[pid] -> [converted_str] [converted_str] ... 
def convert_ebpf_log_to_str(event, ebpf_name):
    try:
        ts = datetime.fromtimestamp(event.timestamp / 1000000000)
        func_name = ct.cast(event.func, ct.c_char_p).value.decode("utf-8")

        try:
            content = ""
            for i in range(event.ebpf_log_section):
                str_text = convert_bytes_to_str(event.sections[i])
                content = content + " [{}]".format(str_text)
        except BaseException as e:
            print(e)

        return "[{}]:[{}]:[{}] {}".format(ebpf_name, func_name, ts, content)
    except:
        return "[{}]:[Failed]".format(ebpf_name)

def log_of_prb_daemon(ebpf_name, attached_ebpf, log_pipe, log_convert_fn=None):

    def log_str_gen(ctx, data, size):
        """
        Generate Log string for polling
        """
        log_str = "Unknown"
        if log_convert_fn:
            log_str = log_convert_fn(ctx, data, size)
        else:
            event = ct.cast(data, ct.POINTER(ebpf_prb_log)).contents
            log_str = convert_ebpf_log_to_str(event, ebpf_name)

        log_pipe.send(log_str)

    attached_ebpf["prb_logs"].open_ring_buffer(log_str_gen)    

    while True:
        try:
            attached_ebpf.ring_buffer_poll()
        except BaseException as e:
            print(ebpf_name, "PRB log thread failed with exception ", e)

def prb_daemon(con_pipe, child_log_pipe, ebpf_name, ebpf_config, log_convert_fn=None):
    """
    Probe Daemon Process 
    """
    if "ebpf" in ebpf_config:
        print("Equipped PRB {}:{}  {}".format(ebpf_name, os.getpid(), ebpf_config["ebpf"]))
    else:
        print("Not existed ebpf prb for {}".format(ebpf_name))
        return

    try:
        attached_bpf = BPF(src_file=ebpf_config["ebpf"])
    except BaseException as e:
        print("failed to load probe ebpf {} with config {}".format(ebpf_name, ebpf_config))
        error_msg = "{}".format(e)
        con_pipe.send('''
        {
            "initialization" : "failed",
            "error_msg": "%s"
        }
        ''' % (error_msg))
        return


    lsm_log_th = threading.Thread(name="prb_log.{}".format(ebpf_name), target=log_of_prb_daemon, args=(ebpf_name, attached_bpf, child_log_pipe, log_convert_fn, ), daemon=True)
    lsm_log_th.start()

    con_pipe.send('''
    {
        "initialization" : "finished"
    }
    ''')

    while True:
        try:
            cmd = con_pipe.recv()
            cmd_json = json.loads(cmd)

            match cmd_json["cmd"]:
                case "list_all_items":
                    result = dict({
                        "cmd_execute_result": "success",
                        "tables": [], 
                        "prbs": []})
                    
                    for tn in attached_bpf:
                        result["tables"].append(tn)
                    for fn in attached_bpf.tracepoint_fds.keys():
                        result["prbs"].append(fn.decode('utf-8'))
                    for fn in attached_bpf.raw_tracepoint_fds.keys():
                        result["prbs"].append(fn.decode('utf-8'))

                    con_pipe.send(json.dumps(result))
                case "exit":
                    print(ebpf_name, "Received command exit, it should be initiated by reload")
                    con_pipe.send('''
                    {
                        "cmd_execute_result": "sucess"
                    }
                    ''')
                    return
                case _:
                    error_msg = "unknown command {}".format(cmd_json)
                    con_pipe.send('''
                    {
                        "cmd_execute_result": "failed",
                        "error_msg": "%s"
                    }
                    ''' % (error_msg))
        except KeyboardInterrupt as k:
            """
            """
        except BaseException as e:
            error_msg = "exception {}".format(e)
            con_pipe.send('''
            {
                "cmd_execute_result": "failed",
                "error_msg": "%s"
            }
            ''' % (error_msg))

class eBPFPRBDaemon:
    def __init__(self, ebpf_name, ebpf_config):
        """
        eBPFPRBDaemon process of the loaded eBPF probe
        """
        log_pipe, child_log_pipe = Pipe()
        parent_pipe, child_pipe = Pipe()
        self.con_pipe = parent_pipe
        self.log_pipe = log_pipe
        self.daemon_proc = Process(target=prb_daemon, name=ebpf_name, args=(child_pipe, child_log_pipe, ebpf_name, ebpf_config, ))
        self.activate = False
        self.ebpf_name = ebpf_name

    def __del__(self):
        print("Exit [{}], cleanup environment".format(self.ebpf_name))
        if self.activate:
            self.daemon_proc.terminate()
            self.daemon_proc.join()

    def get_log_pipe(self):
        return self.log_pipe

    def start(self):
        try:
            self.daemon_proc.start()
            initialization_status = self.con_pipe.recv()
            status = json.loads(initialization_status)
            if status["initialization"] == "finished":
                self.activate = True
                return self.activate
        except BaseException as e:
            print("Not able to start prb daemon process ", self.ebpf_name, " exception: ", e)

        self.activate = False
        self.daemon_proc.terminate()
        self.daemon_proc.join()
        return self.activate

    def list_all_items(self):
        cmd = '''
        { 
            "cmd":"list_all_items"
        }
        '''
        self.con_pipe.send(cmd)
        return self.con_pipe.recv()

    def reload(self, ebpf_name, ebpf_config):
        """
        1. create new ebpf instance
        2. remove existed ebpf instance
        3. no break time of the Probe module
        """
        try:
            log_pipe, child_log_pipe = Pipe()
            parent_pipe, child_pipe = Pipe()
            reloaded_daemon_process = Process(target=prb_daemon, name=ebpf_name, args=(child_pipe, child_log_pipe, ebpf_name, ebpf_config, ))
            reloaded_daemon_process.start()

            initialization_status = parent_pipe.recv()
            status = json.loads(initialization_status)
            if status["initialization"] != "finished":
                return None, {'reload_prb': 'failed', "prb": ebpf_name}
        except BaseException as e:
            """
            """
            return None, {'reload_prb': 'failed', "prb": ebpf_name}

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

        return log_pipe, {'reload_prb' : 'success', 'prb': ebpf_name}


class UmbrellaPRB:
    def __init__(self, ebpf_files, operations=None, events_monitor=None, msg_topics=None):
        """
        Initialize Umbrella PRB userspace
        """
        self.ebpf_daemons = dict({})
        self.providers = dict({})

        self.operations = operations
        self.events_monitor = events_monitor
        self.topics = msg_topics

        log_reload_trigger, log_pipe = Pipe()
        self.log_trigger_pipe = log_reload_trigger
        self.um_prb_log_th = None

        for ebpf_name, ebpf_config in ebpf_files.items():
            self.execute_setup_operation(ebpf_config)
            self.ebpf_daemons[ebpf_name] = eBPFPRBDaemon(ebpf_name, ebpf_config)
            self.update_providers(ebpf_name, ebpf_config)

        self.log_monitor_pipes = []
        self.log_monitor_pipes.append(log_pipe)
        for ebpf_name, ebpf_daemon in self.ebpf_daemons.items():
            self.log_monitor_pipes.append(ebpf_daemon.get_log_pipe())

        self.log_monitor_active = False

    def update_providers(self, ebpf_name, ebpf_config):
        if "providers" in ebpf_config:
            if ebpf_name in self.providers:
                self.providers[ebpf_name].update_config(ebpf_config["providers"])
            else:
                self.providers[ebpf_name] = DataProvider(ebpf_name, ebpf_config["providers"])

    def set_events_monitor(self, events_monitor):
        self.events_monitor = events_monitor

    def start_all(self):
        for _, ebpf_prb in self.ebpf_daemons.items():
            ebpf_prb.start()

        self.log_monitor_active = True
        self.um_prb_log_th = threading.Thread(name="um_prb_log", target=self.log_analysis_loop, daemon=True)
        self.um_prb_log_th.start()

    def clean_all(self):
        print("Clean all loaded PRB, overall {} loaded".format(len(self.ebpf_daemons)))
        self.ebpf_daemons.clear()
        self.log_monitor_active = False
        self.reload_log_pipe()

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

    def list_all(self):
        """
        List all LSM mods
        """
        result = []
        for ebpf_name, ebpf_prb in self.ebpf_daemons.items():
            result.append(ebpf_name)
        
        return result 

    def log_analysis_loop(self):
        while self.log_monitor_active:
            for pipe in wait(self.log_monitor_pipes):
                try:
                    event_item = pipe.recv()
                    event_str = str(event_item)                        
                    prb = event_str[event_str.find("[")+1:event_str.find("]")].strip()
                    if prb in self.providers:
                        self.events_monitor.consume_prb_event(self.providers[prb].convert(event_str[event_str.find("["):]))
                except BaseException as e:
                    self.log_monitor_pipes.remove(pipe)

    def list_details_of_ebpf(self, ebpf_name):
        if ebpf_name in self.ebpf_daemons:
            return self.ebpf_daemons[ebpf_name].list_all_items()
        else:
            return "{}"
        
    def add_ebpf_prb(self, new_prb, ebpf_prb_config):
        """
        Add eBPF Probe
        """
        if new_prb not in self.ebpf_daemons:
            self.execute_setup_operation(ebpf_prb_config)
            new_ebpf_prb = eBPFPRBDaemon(new_prb, ebpf_prb_config)
            self.ebpf_daemons[new_prb] = new_ebpf_prb
            self.ebpf_daemons[new_prb].start()

            self.update_providers(new_prb, ebpf_prb_config)

            self.log_monitor_pipes.append(new_ebpf_prb.get_log_pipe())
            self.reload_log_pipe()
            return { 'add_prb': 'success', "prb": new_prb }
        else:
            return { "add_prb": "failed", "already_existed": new_prb}

    def reload_log_pipe(self):
        self.log_trigger_pipe.send("Refresh log monitor")

    def reload_ebpf_prb(self, reload_prb, ebpf_prb_config):
        """
        Reload already loaded eBPF PRB, runtime update
        """
        if reload_prb in self.ebpf_daemons:
            log_pipe, res = self.ebpf_daemons[reload_prb].reload(reload_prb, ebpf_prb_config)
            if log_pipe != None:
                self.update_providers(reload_prb, ebpf_prb_config)
                self.log_monitor_pipes.append(log_pipe)
                self.reload_log_pipe()
                return res
            else:
                return res
        else:
            return {'reload_prb': "failed", "not_existed": reload_prb}

