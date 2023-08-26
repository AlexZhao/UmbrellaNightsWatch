#!/usr/bin/python
# Apache License V2
# Copyright Zhao Zhe(Alex)
# Runtime Network and Behavior Monitoring on DMZ and Satelite
# 
# Simplified version of runtime kernel monitor compare to umbrella
# based on python without large scale performance consideration
#
# ebpf_task_mon
#    all activities initiated from comm task ID will be recorded 
#
# Consider rename this as microscope to co-work with telescope
#
import sys
import os
import time
import threading
import json
from datetime import datetime

from lsm.um_lsm import UmbrellaLSM
from prb.um_prb import UmbrellaPRB
from pkt.um_pkt import UmbrellaPKT

from analyst.analyst import Analyst
from binary.ld_audit import DynamicLinkingAudit
from operations.operation import NWOperations

from multiprocessing import Process, Pipe
from multiprocessing.connection import wait

import socket
import ctypes
import re

from bcc import BPF

from flask import Flask, request
from flask_restful import reqparse, abort, Resource, Api

from pygtrie import StringTrie

class sockaddr_in(ctypes.Structure):
    _fields_ = [("sa_family", ctypes.c_ushort),  # sin_family
                ("sin_port", ctypes.c_ushort),
                ("sin_addr", ctypes.c_ubyte * 4),
                ("__pad", ctypes.c_byte * 8)]    # struct sockaddr_in is 16 bytes

class sockaddr_in6(ctypes.Structure):
    _fields_ = [("sa_family", ctypes.c_ushort),
                ("sin6_port", ctypes.c_ushort),
                ("sin6_flow", ctypes.c_uint32),
                ("sin6_addr", ctypes.c_uint32 * 4),
                ("sin6_scope_id", ctypes.c_uint32)]

class ev_connect(ctypes.Structure):
    _fields_ = [("comm", ctypes.c_byte * 128),
                ("pid", ctypes.c_int32),
                ("op", ctypes.c_int32),
                ("toc", ctypes.c_int32),
                ("target", sockaddr_in),
                ("targetv6", sockaddr_in6),
                ("path", ctypes.c_byte * 108)]

def from_sockaddr(sockaddr):
    addr = tuple(c for c in sockaddr.sin_addr)
    return ('%d.%d.%d.%d' % addr,
            socket.ntohs(sockaddr.sin_port))

def from_sockaddr6(sockaddr):
    return ("TODO", 0)

class ev_execve(ctypes.Structure):
    _fields_ = [("comm", ctypes.c_byte * 128),
                ("pid", ctypes.c_int32),
                ("filename", ctypes.c_byte * 128),
                ("argv", (ctypes.c_byte * 128) * 10),
                ("argv_cnt", ctypes.c_int32)]

class file_event(ctypes.Structure):
    _fields_ = [("comm", ctypes.c_byte * 64),
                 ("pid", ctypes.c_int32),
                 ("file_op", ctypes.c_int32),
                 ("path", (ctypes.c_byte * 128) * 20),
                 ("depth", ctypes.c_int32)]


def proc_mon_th(proc_pipe):
    proc_mon_bpf = BPF(src_file="./ebpf/ebpf_prb_proc_create.c")

    def callback(ctx, data, size):
        event = ctypes.cast(data, ctypes.POINTER(ev_execve)).contents
        cmd_line = ctypes.cast(event.filename, ctypes.c_char_p).value.decode("utf-8")
        argv_line = ""
        for i in range(event.argv_cnt):
            try:
                argv_line = argv_line + " " + ctypes.cast(event.argv[i], ctypes.c_char_p).value.decode("utf-8")       
            except:
                argv_line = argv_line + " Exception"

        binary_name = cmd_line.rsplit("/")
        
        try:
            comm_name = ctypes.cast(event.comm, ctypes.c_char_p).value.decode("utf-8")
        except:
            comm_name = "Exception"

        proc_pipe.send("{date}:[{comm}] [{pid}]  execv  [{cmdline}] [{argvs}]".format(date=datetime.now(), comm=comm_name, pid=event.pid, cmdline=cmd_line, argvs=argv_line))

    proc_mon_bpf["ring_execve_log"].open_ring_buffer(callback)

    try:
        while True:
            proc_mon_bpf.ring_buffer_poll()
    except KeyboardInterrupt:
        sys.exit()

def tcp_mon_th(tcp_pipe):
    tcp_mon_bpf = BPF(src_file="./ebpf/ebpf_prb_tcp_init.c")

    def tcp_target_check(ctx, data, size):
        event = ctypes.cast(data, ctypes.POINTER(ev_connect)).contents

        op_cmd = "connect"
        if event.op == 2:
            op_cmd = "sendto" 

        target_type = event.toc
        target_ip = "Unknow"
        target_port = "Unknow"

        if target_type == 1:
            try:
                target_ip, target_port = from_sockaddr(event.target)
            except:
                target_ip = "UnknowIPv4"
                target_port = "UnknowPort"    
        elif target_type == 2:
            try:
                target_ip, target_port = from_sockaddr6(event.targetv6)
            except:
                target_ip = "UnknowIPv6"
                target_port = "UnknowPort"
        elif target_type == 3:
            try:
                target_ip = ctypes.cast(event.path, ctypes.c_char_p).value.decode("utf-8")
            except:
                target_ip = "unknown"
            target_port = "unix"
            op_cmd = "connect_un"        

        try:
            comm_name = ctypes.cast(event.comm, ctypes.c_char_p).value.decode("utf-8")
        except:
            comm_name = "Exception"

        tcp_pipe.send("{date}:[{comm}] [{pid}] [{syscall}] --> [{ip}:{port}]".format(date=datetime.now(), comm=comm_name, pid=event.pid, syscall=op_cmd, ip=target_ip, port=target_port))

    tcp_mon_bpf["ring_connect_log"].open_ring_buffer(tcp_target_check)

    try:
        while True:
            tcp_mon_bpf.ring_buffer_poll()
    except KeyboardInterrupt:
        sys.exit()


def dev_event_th(file_pipe):
    dev_bpf = BPF(src_file="./ebpf/ebpf_prb_dev.c")

    def dev_event_check(ctx, data, size):
        try:
            event = ctypes.cast(data, ctypes.POINTER(file_event)).contents
            
            try:
                comm_name = ctypes.cast(event.comm, ctypes.c_char_p).value.decode("utf-8")
            except BaseException as e:
                comm_name = "unknow"

            filename = ""           
            try:
                if event.depth > 0:
                    for i in range(event.depth, -1, -1):
                        filename = filename + "/" + ctypes.cast(event.path[i], ctypes.c_char_p).value.decode("utf-8")
                else:
                    filename = ctypes.cast(event.path[0], ctypes.c_char_p).value.decode("utf-8")
            except:
                filename = "UnknowFile"

            match event.file_op:
                case 1: file_op_name = "open"
                case 2: file_op_name = "ioctl"
                case _: file_op_name = "unknown"

            #if file_op_name == "ioctl":
            #    print(comm_name, " ioctl ", filename, " depth ", event.depth)
            #else:
            #    print(comm_name, " open ", filename)

            file_pipe.send("{date}:[{comm}] [{pid}] [{op}]  [{file}]".format(date=datetime.now(), comm=comm_name, pid=event.pid, op=file_op_name, file=filename))
        except:
            print("Error when file_event_th parse")

    dev_bpf["ring_dev_log"].open_ring_buffer(dev_event_check)

    try:
        while True:
            dev_bpf.ring_buffer_poll()
    except KeyboardInterrupt:
        sys.exit()



def file_event_th(file_pipe):
    file_bpf = BPF(src_file="./ebpf/ebpf_prb_file.c")

    def file_event_check(ctx, data, size):
        try:
            event = ctypes.cast(data, ctypes.POINTER(file_event)).contents
            
            try:
                comm_name = ctypes.cast(event.comm, ctypes.c_char_p).value.decode("utf-8")
            except BaseException as e:
                comm_name = "unknow"

            filename = ""
            if event.depth > 19:
                event.depth = 19
            
            try:
                if event.depth > 0:
                    for i in range(event.depth, -1, -1):
                        filename = filename + "/" + ctypes.cast(event.path[i], ctypes.c_char_p).value.decode("utf-8")
                else:
                    filename = ctypes.cast(event.path[0], ctypes.c_char_p).value.decode("utf-8")
            except:
                filename = "UnknowFile"

            match event.file_op:
                case 1: file_op_name = "open"
                case 2: file_op_name = "ioctl"
                case _: file_op_name = "unknown"

            file_pipe.send("{date}:[{comm}] [{pid}] [{op}]  [{file}]".format(date=datetime.now(), comm=comm_name, pid=event.pid, op=file_op_name, file=filename))
        except:
            print("Error when file_event_th parse")

    file_bpf["ring_file_log"].open_ring_buffer(file_event_check)

    try:
        while True:
            file_bpf.ring_buffer_poll()
    except KeyboardInterrupt:
        sys.exit()


def file_mon_th(file_pipe):
    file_mon_bpf = BPF(src_file="./ebpf/ebpf_prb_file_access.c")

    def file_open_check(ctx, data, size):
        event = file_mon_bpf["ring_file_log"].event(data)
        try:
            file_path = event.filename.decode('utf-8')        
        except:
            file_path = "Exception/"
        
        try:
            comm_name = event.comm.decode('utf-8')
        except:
            comm_name = "Exception"

        file_op = event.file_op
        match file_op:
            case 1: file_op_name = "open"
            case 2: file_op_name = "openat"
            case 3: file_op_name = "openat2"
            case 4: file_op_name = "ioctl"
            case _: file_op_name = "unknown"

        file_pipe.send("{date}:[{comm}] [{pid}] [{op}]  [{file}]".format(date=datetime.now(), comm=comm_name, pid=event.pid, op=file_op_name, file=file_path))

    file_mon_bpf["ring_file_log"].open_ring_buffer(file_open_check)

    try:
        while True:
            file_mon_bpf.ring_buffer_poll()
    except KeyboardInterrupt:
        sys.exit()

def seldom_mon_th(seldom_pipe):
    seldom_mon_bpf = BPF(src_file="./ebpf/ebpf_prb_seldom_syscall.c")

    def seldom_syscall_check(ctx, data, size):
        event = seldom_mon_bpf["ring_seldom_log"].event(data)
        try:
            comm_name = event.comm.decode('utf-8')
        except:
            comm_name = "Exception"

        match event.syscall:
            case 1: syscall = "ptrace"
            case 2: syscall = "modify_ldt"
            case 3: syscall = "enter_personality"
            case 4: syscall = "arch_prctl"
            case 11: syscall = "ioctl"
            case _: syscall = "unknow"

        seldom_pipe.send("{data}:[{comm}] [{pid}] syscall [{syscall}]".format(data=datetime.now(), comm=comm_name, pid=event.pid, syscall=syscall))

    seldom_mon_bpf["ring_seldom_log"].open_ring_buffer(seldom_syscall_check)

    try:
        while True:
            seldom_mon_bpf.ring_buffer_poll()
    except KeyboardInterrupt:
        sys.exit()

def clone_mon_th(clone_pipe):
    clone_mon_bpf = BPF(src_file="./ebpf/ebpf_prb_task.c")

    def clone_open_check(ctx, data, size):
        event = clone_mon_bpf["ring_fork_log"].event(data)
        try:
            comm_name = event.comm.decode('utf-8')
        except:
            comm_name = "Exception"
        
        try:
            new_comm_name = event.new_comm.decode('utf-8')
        except:
            new_comm_name = "Exception"

        event_type = "clone"

        if event.event_type == 1:
            event_type = "clone"
        elif event.event_type == 2:
            event_type = "clone3"
        elif event.event_type == 3:
            event_type = "new_task"
        elif event.event_type == 4:
            event_type = "task_rename"
        else:
            event_type = "task_exit"
        
        clone_pipe.send("{date}:[{comm}]  [{fork_type}]  [{new_comm}] [{parent_pid}] -> [{child_pid}]".format(date=datetime.now(), comm=comm_name, fork_type=event_type, new_comm=new_comm_name, parent_pid=event.parent_pid, child_pid=event.child_pid))

    clone_mon_bpf["ring_fork_log"].open_ring_buffer(clone_open_check)

    try:
        while True:
            clone_mon_bpf.ring_buffer_poll()
    except KeyboardInterrupt:
        sys.exit()

# TODO Main part on the fly modifable 
class ApplicationProfile:
    def __init__(self, app):
        self.app = app
        # Trie Tree easy for traverse
        self.file_access = StringTrie(separator="/")
        self.dev_access = dict({})
        # Connect/sendto not able to distinguish TCP/UDP
        self.net_access = dict({"TCP":{},
                                "UDP":{},
                                "UNIX":{}})
        self.execv_cmd = dict({})
        self.seldom_syscall = dict({})
        self.pids = dict({})
        self.file_record_pattern = StringTrie(separator="/")
        
        self.file_record_pattern["/home"] = 4
        self.file_record_pattern["/var/tmp"] = 5
        self.file_record_pattern["/var/log"] = 5
        self.file_record_pattern["/var/cache"] = 5
        self.file_record_pattern["/tmp"] = 3
        self.file_record_pattern["/dev/shm"] = 4
        self.file_record_pattern["/usr/share"] = 4
        self.file_record_pattern["/usr/local/share"] = 5

    def need_record_full_file(self, file_loc):
        key, val = self.file_record_pattern.longest_prefix(file_loc)
        if key:
            try:
                if file_loc.endswith(".py"):
                    return file_loc
                else:
                    file_loc = file_loc[:file_loc.rfind('/')]
                
                    depth = val
                    idx = -1
                    for i in range(0, depth):
                        idx = file_loc.find("/", idx + 1)
                        if idx == -1:
                            return file_loc                    
                    return file_loc[:idx]
            except:
                return file_loc 
        else:
            return file_loc

    def add_file_access(self, file_op, file_loc):
        """
        Except disk scanner, file access should be simple 
        """
        if file_op == "ioctl":
            # track device ioctl associate with application, associate with device map
            if file_loc in self.dev_access:
                self.dev_access[file_loc] = self.dev_access[file_loc] + 1
            else:
                self.dev_access[file_loc] = 1
        elif file_op != "unknow":

            file_loc = self.need_record_full_file(file_loc)
            
            if self.file_access.has_key(file_loc):
                self.file_access[file_loc] = self.file_access[file_loc] + 1
            else:
                self.file_access[file_loc] = 1

    def add_net_access(self, syscall, target):
        """
        Except network scanner, app network access should be simple
        limit network access 
        """
        if syscall == "connect":
            if target in self.net_access["TCP"]:
                self.net_access["TCP"][target] = self.net_access["TCP"][target] + 1
            else:
                self.net_access["TCP"][target] = 1
        elif syscall == "connect_un":
            if target in self.net_access["UNIX"]:
                self.net_access["UNIX"][target] = self.net_access["UNIX"][target] + 1
            else:
                self.net_access["UNIX"][target] = 1
        else:
            if target in self.net_access["UDP"]:
                self.net_access["UDP"][target] = self.net_access["UDP"][target] + 1
            else:
                self.net_access["UDP"][target] = 1

    def add_cmd_execute(self, bin, cmdline):
        """
        Execve invoked from process
        """
        if bin in self.execv_cmd:
            if cmdline in self.execv_cmd[bin]:
                self.execv_cmd[bin][cmdline] = self.execv_cmd[bin][cmdline] + 1
            else:
                self.execv_cmd[bin][cmdline] = 1
        else:
            self.execv_cmd[bin] = dict({cmdline: 1})

    def add_seldom_syscall(self, syscall):
        """
        Seldom syscall
        """
        if syscall in self.seldom_syscall:
            self.seldom_syscall[syscall] = self.seldom_syscall[syscall] + 1
        else:
            self.seldom_syscall[syscall] = 1

    def add_proc_tree(self, taskinfo):
        """
        Monitor all parents/child process forked
        """


    def dump_app_profile(self):
        result = dict({})
        
        file_access_result = []
        for path in self.file_access.keys():
            if self.file_access[path] > 0:
                file_access_result.append(dict({path: self.file_access[path]}))

        result["file_access"] = file_access_result

        result["dev_access"] = self.dev_access

        result["net_access"] = self.net_access

        result["execv_access"] = self.execv_cmd            

        result["seldom_syscall"] = self.seldom_syscall

        return result

class EventsMonitor:
    def __init__(self):
        self.debug = False
        self.mon_proc_details = dict({})
        # Empty for some smart work
        self.file_access_re = re.compile("([\d\-\:\s\.]+)\:\[([\w\W]+)\] \[(\d+)\] \[([\w\W]+)\]  \[([\w\W]*)\]", re.IGNORECASE)
        self.network_access_re = re.compile("([\d\-\:\s\.]+)\:\[([\w\W]+)\] \[(\d+)\] \[([\w]+)\] --> \[([\w\W]+)\]", re.IGNORECASE)
        self.execv_access_re = re.compile("([\d\-\:\s\.]+)\:\[([\w\W]+)\] \[(\d+)\]  execv  \[([\w\W]+)\] \[([\w\W]*)\]", re.IGNORECASE)
        self.task_create_re = re.compile("([\d\-\:\s\.]+)\:\[([\w\W]+)\]  \[([\w\W]+)\]  \[([\w\W]*)\] \[(\d+)\] -> \[(\d+)\]", re.IGNORECASE)
        self.seldom_access_re = re.compile("([\d\-\:\s\.]+)\:\[([\w\W]+)\] \[(\d+)\] syscall \[([\w\W]+)\]", re.IGNORECASE)
        self.audit_log_path = "/var/log/runtime_mon.log"
        self.audit_file = open(self.audit_log_path, "a")
        self.pid_comm_maps = dict({})
        self.config_file = ""
        self.config = dict({})
        self.prb = None
        self.lsm = None
        self.analyst = None
        self.mon_ignore_list = dict({})
        self.operations = NWOperations()
        self.device_map = self.operations.execute_operation("dev", "scan_device_map")
        self.dev_access = dict({})
        self.pipes = dict({})
        self.provider_pipes = []

    def create_pipes(self, config):
        for pipe_name in config:
            p, c = Pipe()
            self.pipes[pipe_name] = (p, c)

    def get_consumer_pipe(self, pipe_name):
        if pipe_name in self.pipes:
            return self.pipes[pipe_name][1]
        else:
            return None

    def get_provider_pipe(self, pipe_name):
        if pipe_name in self.pipes:
            return self.pipes[pipe_name][0]
        else:
            return None

    def record_audit_log(self, log):
        self.audit_file.write("[{}]: {}\n".format(datetime.now(), log))
        self.audit_file.flush()

    def update_audit_log_path(self, audit_log_path):
        if audit_log_path != self.audit_log_path:
            self.audit_log_path = audit_log_path
            self.audit_file.close()
            self.audit_file = open(self.audit_log_path, "a")

    def update_audit_log_enabled(self, enabled):
        self.audit_log_enabled = enabled

    def set_config(self, config_file, config):
        self.config_file = config_file
        self.config = config

    def get_config_file(self):
        return self.config_file

    def add_mon_proc(self, comm):
        if not comm in self.mon_proc_details and not comm in self.mon_ignore_list:
            self.mon_proc_details[comm] = ApplicationProfile(comm)

    def set_prb_controller(self, prb):
        self.prb = prb

    def get_prb_controller(self):
        return self.prb

    def set_lsm_controller(self, lsm):
        self.lsm = lsm

    def get_lsm_controller(self):
        return self.lsm

    def set_analyst_engine(self, analyst):
        self.analyst = analyst
        if self.lsm:
            self.lsm.set_analyst(analyst)
    
    def get_analyst_engine(self):
        return self.analyst

    def is_prb_active(self):
        if self.prb != None:
            return True
        else:
            return False

    def is_lsm_active(self):
        if self.lsm != None:
            return True
        else:
            return False

    def set_mon_ignore_list(self, ignore_list):
        self.mon_ignore_list = ignore_list

    def dump_mon_proc(self, comm):
        """
        Dump all Monitoring Process details access 
         Filesystem Access
         Execv command
         Network Access
        """
        if comm in self.mon_proc_details:
            return self.mon_proc_details[comm].dump_app_profile()
        else:
            return dict({"not result": comm})

    def list_mon_proc(self):
        """
        List all under Monitoring processes
        """
        all_mon_proc = []
        for comm in self.mon_proc_details.keys():
            all_mon_proc.append(comm)
        
        return all_mon_proc

    def list_dev_access(self):
        """
        List all device direct access details
        """
        access_details = dict({})
        for dev, access in self.dev_access.items():
            if dev in self.device_map:
                access_details[dev] = dict({
                    "device": self.device_map[dev],
                    "access": access 
                })

        return access_details

    def log_analysis_loop(self):
        try:
            while self.provider_pipes:
                for pipe in wait(self.provider_pipes):
                    try:
                        event_item = pipe.recv()
                        # Consume event log
                    except BaseException as e:
                        self.provider_pipes.remove(pipe)
        except KeyboardInterrupt:
            sys.exit()


    def update_mon_proc_file_access(self, comm, pid, file_op, file_loc):
        # Update direct device access
        if file_op == "ioctl":
            dev_name = file_loc[file_loc.rfind('/') + 1:]
            if dev_name in self.dev_access:
                if comm in self.dev_access[dev_name]:
                    self.dev_access[dev_name][comm] = self.dev_access[dev_name][comm] + 1
                else:
                    self.dev_access[dev_name][comm] = 1
            else:
                self.dev_access[dev_name] = dict({ comm : 1})

        if comm in self.mon_proc_details:
            self.mon_proc_details[comm].add_file_access(file_op, file_loc)
        else:    
            self.add_mon_proc(comm)
            self.mon_proc_details[comm].add_file_access(file_op, file_loc)

    def update_mon_proc_net_access(self, comm, pid, syscall, target):
        if comm in self.mon_proc_details:
            self.mon_proc_details[comm].add_net_access(syscall, target)
        else:
            self.add_mon_proc(comm)
            self.mon_proc_details[comm].add_net_access(syscall, target)

    def update_mon_proc_execv_access(self, comm, pid, bin, cmdline):
        if comm in self.mon_proc_details:
            self.mon_proc_details[comm].add_cmd_execute(bin, cmdline)
        else:
            self.add_mon_proc(comm)
            self.mon_proc_details[comm].add_cmd_execute(bin, cmdline)

    def update_task_tree(self, comm, op, new_comm, pid, child_pid):
        """
        Update task tree
        """
        if comm in self.mon_proc_details:
            if op == "new_task":
                self.pid_comm_maps[child_pid] = comm
            elif op == "task_exit":
                del self.pid_comm_maps[pid]

    def update_seldom_syscall(self, comm, pid, syscall, timestamp):
        """
        Update the Seldom Syscall Access
        """
        if comm in self.mon_proc_details:
            self.mon_proc_details[comm].add_seldom_syscall(syscall)
        else:
            self.add_mon_proc(comm)
            self.mon_proc_details[comm].add_seldom_syscall(syscall)
        
    def parse_audit_log(self, log):
        """
        Direct Parse the Monitoring events from audit log
        """
        try:
            file_access_match = self.file_access_re.match(log)
            if file_access_match:
                timestamp = file_access_match.group(1)
                comm = file_access_match.group(2)
                pid = file_access_match.group(3)
                file_op = file_access_match.group(4)
                file_loc = file_access_match.group(5)
                self.update_mon_proc_file_access(comm, pid, file_op, file_loc)

            net_access_match = self.network_access_re.match(log)
            if net_access_match:
                timestamp = net_access_match.group(1)
                comm = net_access_match.group(2)
                pid = net_access_match.group(3)
                syscall_op = net_access_match.group(4)
                target = net_access_match.group(5)
                self.update_mon_proc_net_access(comm, pid, syscall_op, target)

            execv_access_match = self.execv_access_re.match(log)
            if execv_access_match:
                timestamp = execv_access_match.group(1)
                comm = execv_access_match.group(2)
                pid = execv_access_match.group(3)
                bin = execv_access_match.group(4)
                cmdline = execv_access_match.group(5)
                self.update_mon_proc_execv_access(comm, pid, bin, cmdline)

            task_create_match = self.task_create_re.match(log)
            if task_create_match:
                timestamp = task_create_match.group(1)
                comm = task_create_match.group(2)
                op = task_create_match.group(3)
                new_comm = task_create_match.group(4)
                pid = task_create_match.group(5)
                child_pid = task_create_match.group(6)
                self.update_task_tree(comm, op, new_comm, pid, child_pid)
            
            seldom_syscall_match = self.seldom_access_re.match(log)
            if seldom_syscall_match:
                timestamp =seldom_syscall_match.group(1)
                comm = seldom_syscall_match.group(2)
                pid = seldom_syscall_match.group(3)
                syscall = seldom_syscall_match.group(4)
                self.update_seldom_syscall(comm, pid, syscall, timestamp)

        except Exception as e: 
            # There is something not captured, so here is exceptions
            print("Parse log Failed with exception  ", e)

        if self.analyst:
            self.analyst.consume(log)

    def close_log(self):
        self.audit_file.close()

events_monitor = EventsMonitor()

def log_analysis_loop(all_pipes):
    try:
        while all_pipes:
            for pipe in wait(all_pipes):
                try:
                    event_item = pipe.recv()
                except EOFError:
                    all_pipes.remove(pipe)
                else:
                    events_monitor.parse_audit_log(event_item)
    except KeyboardInterrupt:
        events_monitor.close_log()
        sys.exit()

parser = reqparse.RequestParser()
parser.add_argument('proc', type=str, location='args')

class DumpMonDetails(Resource):
    def get(self):
        return {'usage': "POST to dump monitoring details of process"}
    def post(self):
        """
        POST dump monitoring details
        """
        dump_proc_comm = parser.parse_args()['proc']
        if dump_proc_comm:
            dump_result = events_monitor.dump_mon_proc(dump_proc_comm)
            return {'result': "success", "details": dump_result}
        else:
            return {'result': "failed", "details": "Not correct URL request"}

class ListMonProc(Resource):
    def get(self):
        """
        GET to list all process under monitor
        """
        mon_procs = events_monitor.list_mon_proc()
        return {'result': "success", "details": mon_procs}

class ListDevAccess(Resource):
    def get(self):
        """
        Get to list all device access direct by applciation on host
        """
        dev_access = events_monitor.list_dev_access()
        return {'result': "success", "details": dev_access}

class LSM(Resource):
    def get(self):
        """
        Check is LSM supported under RuntimeMonitor
        """
        if events_monitor.is_lsm_active():
            result = events_monitor.get_lsm_controller().list_all()
            return {'result': 'success', 'details': result}
        else:
            return {'result': 'success', 'details': 'NO LSM activate'}
    def post(self):
        """
        Post to add/del LSM modules 
        TODO add/delete operation need to recorded
        """
        command = request.form['cmd']
        match command:
            case "add_ebpf_lsm":
                try:
                    new_lsm = request.form['lsm']
                    if "config" in request.form:
                        config_file = request.form['config']
                    else:
                        config_file = events_monitor.get_config_file()
                        
                    config_content = open(config_file)
                    config = json.load(config_content)
    
                    if "umbrella_lsm" in config:
                        lsm_config = config["umbrella_lsm"]
                    else:
                        lsm_config = config      

                    if new_lsm in lsm_config:
                        ebpf_lsm_config = lsm_config[new_lsm]
                    else:
                        return {'result': 'failed', 'details': 'addd_lsm, no configuration existed for {}'.format(new_lsm)}

                    result = events_monitor.get_lsm_controller().add_ebpf_lsm(new_lsm, ebpf_lsm_config)
                    events_monitor.record_audit_log("add_ebpf_lsm : {}  [{}]".format(new_lsm, ebpf_lsm_config))
                    return result
                except BaseException as e:
                    return {'result': 'failed', 'details': 'add_lsm, not correct command format {}'.format(e)}
            case _:
                return {'result': 'failed', 'details': "Not supported command {}".format(command)}
            


class LSMOp(Resource):
    def get(self, lsm_ebpf):
        """
        Check equipped LSM configurable item
        """
        if events_monitor.is_lsm_active():
            result = events_monitor.get_lsm_controller().list_details_of_ebpf(lsm_ebpf)
            return {'result': 'success', 'details': result}
        else:
            return {'result': 'failed', 'details': 'LSM not activate'}
    def post(self, lsm_ebpf):
        """
        Post to configure the target LSM item 
        TODO reload operation need to recorded
        """
        if events_monitor.is_lsm_active():
            command = request.form['cmd']
            match command:
                case "update_config":
                    try:
                        map = request.form['map']
                        key = request.form['key']
                        value = request.form['value']
                        if "key_convert" in request.form:
                            key_convert = request.form["key_convert"]
                        else:
                            key_convert = "None"
                        
                        if "value_convert" in request.form:
                            value_convert = request.form["value_convert"]
                        else:
                            value_convert = "None"
                        result = events_monitor.get_lsm_controller().update_lsm_config(lsm_ebpf, map, key, value, key_convert, value_convert)
                        events_monitor.record_audit_log("update_lsm_config : {}  [{}:{}]".format(lsm_ebpf, key, value))
                        return result
                    except BaseException as e:
                        return {'result': 'failed', 'details': 'update_lsm_config, Not correct command format {}'.format(e)}
                case "delete_config":
                    try:
                        map = request.form['map']
                        key = request.form['key']
                        if "value" in request.form:
                            value = request.form["value"]
                        else:
                            value = "None"

                        if "key_convert" in request.form:
                            key_convert = request.form["key_convert"]
                        else:
                            key_convert = "None"

                        if "value_convert" in request.form:
                            value_convert = request.form["value_convert"]
                        else:
                            value_convert = "None"
                        
                        result = events_monitor.get_lsm_controller().delete_lsm_config(lsm_ebpf, map, key, value, key_convert, value_convert)
                        events_monitor.record_audit_log("delete_lsm_config : {}  [{}:{}]".format(lsm_ebpf, key, value))
                        return result
                    except BaseException as e:
                        return {'result': 'failed', 'details': 'delete_lsm_config, not correct command format {}'.format(e)}
                case "reload_ebpf_lsm":
                    try:
                        if "config" in request.form:
                            config_file = request.form['config']
                        else:
                            config_file = events_monitor.get_config_file()

                        config_content = open(config_file)
                        config = json.load(config_content)
                        
                        if "umbrella_lsm" in config:
                            lsm_config = config["umbrella_lsm"]
                        else:
                            lsm_config = config                            

                        if lsm_ebpf in lsm_config:
                            ebpf_lsm_config = lsm_config[lsm_ebpf]
                        else:
                            return {'result': 'failed', 'details': 'reload_lsm, no configuration existed for {}'.format(lsm_ebpf)}

                        result = events_monitor.get_lsm_controller().reload_ebpf_lsm(lsm_ebpf, ebpf_lsm_config)
                        events_monitor.record_audit_log("reload_ebpf_lsm : {}  [{}]".format(lsm_ebpf, ebpf_lsm_config))
                        return result
                    except BaseException as e:
                        return {'result': 'failed', 'details': 'reload_lsm, not correct command format {}'.format(e)}
                case _:
                    return {'result': 'failed', 'details': "Not supported command {}".format(command)}
        else:
            return {'result': 'failed', 'details': 'LSM not activate'}

class PRB(Resource):
    def get(self):
        """
        Check is PRB supported under RuntimeMonitor
        """
        if events_monitor.is_prb_active():
            result = events_monitor.get_prb_controller().list_all()
            return {'result': 'success', 'details': result}
        else:
            return {'result': 'success', 'details': 'NO LSM activate'}
    def post(self):
        """
        Post to add/del PRB modules 
        TODO add/delete operation need to recorded
        """
        command = request.form['cmd']
        match command:
            case "add_ebpf_prb":
                try:
                    new_prb = request.form['prb']
                    if "config" in request.form:
                        config_file = request.form['config']
                    else:
                        config_file = events_monitor.get_config_file()
                        
                    config_content = open(config_file)
                    config = json.load(config_content)
    
                    if "umbrella_prb" in config:
                        prb_config = config["umbrella_prb"]
                    else:
                        prb_config = config      

                    if new_prb in prb_config:
                        ebpf_prb_config = prb_config[new_prb]
                    else:
                        return {'result': 'failed', 'details': 'addd_prb, no configuration existed for {}'.format(new_prb)}

                    result = events_monitor.get_prb_controller().add_ebpf_prb(new_prb, ebpf_prb_config)
                    events_monitor.record_audit_log("add_ebpf_prb : {}  [{}]".format(new_prb, ebpf_prb_config))
                    return result
                except BaseException as e:
                    return {'result': 'failed', 'details': 'add_prb, not correct command format {}'.format(e)}
            case _:
                return {'result': 'failed', 'details': "Not supported command {}".format(command)}


class PRBOp(Resource):
    def get(self, prb_ebpf):
        """
        Check PRB status
        """
        if events_monitor.is_prb_active():
            result = events_monitor.get_prb_controller().list_details_of_ebpf(prb_ebpf)
            return {'result': 'success', 'details': result}
        else:
            return {'result': 'failed', 'details': 'LSM not activate'}
    def post(self, prb_ebpf):
        """
        Config PRB
        """
        if events_monitor.is_prb_active():
            command = request.form['cmd']
            match command:
                case "reload_ebpf_prb":
                    try:
                        if "config" in request.form:
                            config_file = request.form['config']
                        else:
                            config_file = events_monitor.get_config_file()

                        config_content = open(config_file)
                        config = json.load(config_content)

                        if "umbrella_prb" in config:
                            prb_config = config["umbrella_prb"]
                        else:
                            prb_config = config
                    
                        if prb_ebpf in prb_config:
                            ebpf_prb_config = prb_config[prb_ebpf]
                        else:
                            return {'result':'failed', 'details': 'reload_prb, no configuration existed for {}'.format(prb_ebpf)}
                    
                        result = events_monitor.get_prb_controller().reload_ebpf_prb(prb_ebpf, ebpf_prb_config)
                        events_monitor.record_audit_log("reload_ebpf_prb: {} [{}]".format(prb_ebpf, ebpf_prb_config))
                        return result
                    except BaseException as e:
                        return {'result':'failed', 'details': 'reload_prb, not correct command format {}'.format(e)}
                case _: 
                    return {'result': 'failed', 'details': "Not supported command {}".format(command)}
        else:
            return {'result':'failed', 'details': 'PRB not activate'}

app = Flask(__name__)
api = Api(app)

api.add_resource(DumpMonDetails, '/dump_mon')
api.add_resource(ListMonProc, '/list_mon')
api.add_resource(ListDevAccess, '/list_dev_access')


# Dynamic modifiable LSM 
api.add_resource(LSM, '/lsm')
api.add_resource(LSMOp, '/lsm/<string:lsm_ebpf>')

# Dynamic modifiable PRB
api.add_resource(PRB, '/prb')
api.add_resource(PRBOp, '/prb/<string:prb_ebpf>')

if __name__ == '__main__':
    sched_params = os.sched_param(os.sched_get_priority_max(os.SCHED_RR))
    os.sched_setscheduler(0, os.SCHED_RR, sched_params)

    config_file = open('./conf/runtime_mon.conf')

    config = json.load(config_file)

    config_file.close()

    # Reserve Logic for ignore/critical list  
    # ignore list will record all the stuffs not in ignore list
    # critical list will record all the stuffs in critical list
    mon_ignore_task_list = dict({})
    for task in config["ebpf_task_mon"]["ignore_list"]:
        mon_ignore_task_list[task] = True
    
    events_monitor.set_mon_ignore_list(mon_ignore_task_list)

    # Log used for context analysis without statistics
    if "audit_log_path" in config:
        events_monitor.update_audit_log_path(config["audit_log_path"])
    
    if "audit_log_enabled" in config:
        events_monitor.update_audit_log_enabled(config["audit_log_enabled"])

    if "pipes" in config:
        events_monitor.create_pipes(config["pipes"])

    events_monitor.set_config('./conf/runtime_mon.conf', config)

    # used by runtime mon to trace back to only allow runtime_mon use BPF interface
    # for eBPF security reason.
    runtime_mon_pid = os.getppid()
    
    if "bpf_lsm" in config["umbrella_lsm"]:
        print("NW PID {}".format(runtime_mon_pid))
        config["umbrella_lsm"]["bpf_lsm"]["runtime_mon_pid"] = runtime_mon_pid


    all_pipes = []
    proc_mon_conn, proc_mon_child_conn = Pipe()
    proc_mon = Process(target=proc_mon_th, args=(proc_mon_child_conn, ))
    proc_mon.start()
    all_pipes.append(proc_mon_conn)

    tcp_mon_conn, tcp_mon_child_conn = Pipe()
    tcp_mon = Process(target=tcp_mon_th, args=(tcp_mon_child_conn, ))
    tcp_mon.start()
    all_pipes.append(tcp_mon_conn)

    file_ev_conn, file_ev_child_conn = Pipe()
    file_ev = Process(target=file_event_th, args=(file_ev_child_conn, ))
    file_ev.start()
    all_pipes.append(file_ev_conn)

    dev_ev_conn, dev_ev_child_conn = Pipe()
    dev_ev = Process(target=dev_event_th, args=(dev_ev_child_conn, ))
    dev_ev.start()
    all_pipes.append(dev_ev_conn)

    #clone_mon_conn, clone_mon_child_conn = Pipe()
    #clone_mon = Process(target=clone_mon_th, args=(clone_mon_child_conn, ))
    #clone_mon.start()
    #all_pipes.append(clone_mon_conn)

    seldom_mon_conn, seldom_mon_child_conn = Pipe()
    seldom_mon = Process(target=seldom_mon_th, args=(seldom_mon_child_conn, ))
    seldom_mon.start()
    all_pipes.append(seldom_mon_conn)

    log_analysis_th = threading.Thread(name="eBPF audit", target=log_analysis_loop, args=(all_pipes, ))
    log_analysis_th.start()

    nw_operations = NWOperations()

    um_prb_daemon = UmbrellaPRB(config["umbrella_prb"], nw_operations)
    um_prb_daemon.start_all()
    events_monitor.set_prb_controller(um_prb_daemon)

    um_lsm_daemon = UmbrellaLSM(config["umbrella_lsm"], nw_operations)
    um_lsm_daemon.start_all()
    events_monitor.set_lsm_controller(um_lsm_daemon)

    um_pkt_daemon = UmbrellaPKT(config["umbrella_pkt"], nw_operations)
    um_pkt_daemon.start_all()

    ld_audit_daemon = DynamicLinkingAudit(config["ld_bindings_audit"])
    ld_audit_daemon.start_mon_ld_log()

    analyst_daemon = Analyst(config["analyst"])
    events_monitor.set_analyst_engine(analyst_daemon)

    # Port Short for RuntimeMonitor RM in ASCII
    app.run(debug=False, port=8277)

    while True:
        time.sleep(100)

