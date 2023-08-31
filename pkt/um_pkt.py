#!/usr/bin/python
#
# Apache License V2
# Copyright Alex Zhao
#
# Simplified version of Umbrella
#  Packet filter
#  sockfilter  socket_fd
#  xdpfilter perf_output (xdp_output)
# attach to interface
#
from bcc import BPF

import os
import json
import sys
import threading
import ctypes as ct
import time
import pyroute2

from datetime import datetime

from multiprocessing import Process, Pipe;
from multiprocessing.connection import wait;

from pkt.pkt2json import PKT2JSON

class eBPFPKTLog:
    def __init__(self, ebpf_name, ebpf_log):
        self.log_name = ebpf_name
        self.config = ebpf_log
        self.log_file = None
        self.flush_threshold = 100
        self.flush_cnt = self.flush_threshold

        if "file" in ebpf_log:
            try:
                self.log_file_name = ebpf_log["file"]
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
    
        self.truncate_interval_secs = 0
        self.active_pkt_log_daemon = False

        if "truncate" in ebpf_log:
            self.truncate_interval_secs = 60 * 60
            try:
                if ebpf_log["truncate"].endswith("day"):
                    end_of_int = ebpf_log["truncate"].find("day")
                    self.truncate_interval_secs = int(ebpf_log["truncate"][:end_of_int]) * 24 * 60 * 60
                elif ebpf_log["truncate"].endswith("hour"):
                    end_of_int = ebpf_log["truncate"].find("hour")
                    self.truncate_interval_secs = int(ebpf_log["truncate"][:end_of_int]) * 60 * 60
                elif ebpf_log["truncate"].endswith("min"):
                    end_of_int = ebpf_log["truncate"].find("min")
                    self.truncate_interval_secs = int(ebpf_log["truncate"][:end_of_int]) * 60
            except BaseException as e:
                print("parse log file truncate failed ", e, " default value 1 hour used")
            self.active_pkt_log_daemon = True

        if self.active_pkt_log_daemon:
            self.pkt_log_daemon_th = threading.Thread(name="pkt_log", target=self.pkt_log_daemon_thread)
            self.pkt_log_daemon_th.start()

    def pkt_log_daemon_thread(self):
        """
        Packet log monitoring thread
        """
        truncate_pass_time = 0
        while self.active_pkt_log_daemon:
            if self.truncate_interval_secs > 0 and truncate_pass_time > self.truncate_interval_secs:
                try:
                    self.log_file.truncate(0)
                except BaseException as e:
                    print("Not able to truncate packet capture log file  ", self.log_file_name, e)
                truncate_pass_time = 0

            # Every minutes is the minimum interval
            time.sleep(60)
            truncate_pass_time += 60

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


class MetaData(ct.Structure):
    _fields_ = [("timestamp", ct.c_uint64),
                ("pkt_len", ct.c_uint32),
                ("pkt_type", ct.c_uint16),
                ("pkt_offset", ct.c_uint16)]


def pkt_perf_output_thread(ebpf_name, attached_ebpf, output_map, log_pipe, log_convert_fn=None):
    def print_event(cpu, data, size):
        class SkbEvent(ct.Structure):
            _fields_ =  [ ("meta", MetaData),
                          ("pkt", ct.c_ubyte * (size - ct.sizeof(MetaData))) ]
        
        skb_event = ct.cast(data, ct.POINTER(SkbEvent)).contents
        ts = datetime.fromtimestamp(skb_event.meta.timestamp / 1000000000)
        timestamp = "{}.{}".format(ts.strftime('%Y-%m-%d %H:%M:%S'), str(int(skb_event.meta.timestamp % 1000000000)).zfill(9))

        offset = skb_event.meta.pkt_offset
        serilized_pkt = PKT2JSON.parse(skb_event.meta.pkt_type, skb_event.meta.pkt_len, offset, skb_event.pkt)
        serilized_pkt["timestamp"] = timestamp

        log = "{} -> {}".format(ebpf_name, json.dumps(serilized_pkt))
        log_pipe.send(log)

    attached_ebpf[output_map].open_perf_buffer(print_event)
    while True:
        try:
            attached_ebpf.perf_buffer_poll()
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
def pkt_daemon(con_pipe, child_log_pipe, ebpf_name, ebpf_config, log_convert_fn=None):
    """
    LSM Daemon Process
    """
    if "ebpf" in ebpf_config:
        print("Equipped Packet Filter {}:{}  {}".format(ebpf_name, os.getpid(), ebpf_config["ebpf"]))
    else:
        print("Not existed ebpf packet filter for {}".format(ebpf_name))
        return

    try:
        pkt_filter_bpf = BPF(src_file=ebpf_config["ebpf"])
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

    # Attach eBPF to sock or XDP
    try:
        error_msg = None
        if "pkt_parsers" in ebpf_config:
            for pkt_config in ebpf_config["pkt_parsers"]:
                print(pkt_config)
                if "pkt_type" in pkt_config:
                    try:
                        match pkt_config["pkt_type"]:
                            case "xdp":
                                if "pkt_parser" in pkt_config:
                                    fn = pkt_filter_bpf.load_func(pkt_config["pkt_parser"], BPF.XDP, None)
                                    if "interfaces" in pkt_config:
                                        for interface in pkt_config["interfaces"]:
                                            pkt_filter_bpf.attach_xdp(interface, fn, BPF.XDP_FLAGS_SKB_MODE)
                                            print("Attached {} on {}".format(pkt_config["pkt_parser"], interface))
                                    else:
                                        error_msg = "No configured interfaces  for xdp to attach"
                                else:
                                    error_msg = "No configured pkt_parser  function entry for xdp"
                            case "classifier":
                                if "pkt_parser" in pkt_config:
                                    fn = pkt_filter_bpf.load_func(pkt_config["pkt_parser"], BPF.SCHED_CLS, None)
                                    if "interfaces" in pkt_config:
                                        ipr = pyroute2.IPRoute()
                                        for interface in pkt_config["interfaces"]:
                                            intf = ipr.link_lookup(ifname=interface)[0]
                                            # Not working well with add sfq and filter, simple filter only 
                                            ipr.tc("replace", "sfq", intf, "1:")
                                            # Filter require to have cls_bpf and sch_sfq kernel mod
                                            ipr.tc("replace-filter", "bpf", intf, ":1", parent="1:", fd=fn.fd, name=fn.name, classid=1)
                            case _:
                                error_msg = "Unkonw pkt_type in config it need to be xdp/..."
                    except BaseException as e:
                        print("Attach packet filter to interface failed with exception ", e)
        if error_msg is not None:
            print("wrong configured pkt filter ebpf {} with config {}, erro {}".format(ebpf_name, ebpf_config, error_msg))
            con_pipe.send('''
            {
                "initialization" : "failed",
                "error_msg": "%s"
            }
            ''' % (error_msg))
            return 

    except BaseException as e:
        concate_error_msg = "{}".format(e)
        print("Exception when attach xdp ebpf filter {} with config {}, error {}".format(ebpf_name, ebpf_config, concate_error_msg))
        con_pipe.send('''
        {
            "initialization" : "failed",
            "error_msg": "%s"
        }
        ''' % (concate_error_msg))
        return 

    con_pipe.send('''
    {
        "initialization" : "finished"
    }
    ''')

    pkt_outputs_threads = dict({})
    pkt_outputs_threads["perf"] = dict({})

    if "pkt_outputs" in ebpf_config:
        for output in ebpf_config["pkt_outputs"]:
            for output_type, output_map in output.items():
                match output_type:
                    case "perf_output":
                        try:
                            perf_th = threading.Thread(name="pkt.{}".format(output_map), target=pkt_perf_output_thread, args=(ebpf_name, pkt_filter_bpf, output_map, child_log_pipe, log_convert_fn, ))
                            perf_th.start()
                            pkt_outputs_threads["perf"][output_map] = perf_th
                        except BaseException as e:
                            print("Start Perf output filter thread failed with exception {}", e)
                    case _:
                        print("Not supported output config {}:{}", output_type, output_map)
    else:
        print("This is a pkt filter without filter out data")

    try:
        while True:
            cmd = con_pipe.recv()
            cmd_json = json.loads(cmd)
            try:
                match cmd_json["cmd"]:
                    
                    case _:
                        con_pipe.send("{'cmd_execute_result': 'unknown command'}")
            except BaseException as e:
                con_pipe.send('''
                {
                    "cmd_execute_result": "failed",
                    "error": "update command not correct format %s"
                }
                ''' % (cmd_json))
                print("Not able to process {}".format(cmd_json))
    except KeyboardInterrupt:
        sys.exit()
        


class eBPFPKTDaemon:
    def __init__(self, ebpf_name, ebpf_config):
        """
        eBPF Packet Daemon Process
        """
        log_pipe, child_log_pipe = Pipe()
        parent_pipe, child_pipe = Pipe()
        self.con_pipe = parent_pipe
        self.log_pipe = log_pipe

        self.daemon_proc = Process(target=pkt_daemon, name=ebpf_name, args=(child_pipe, child_log_pipe, ebpf_name, ebpf_config, ))


    def start(self):
        """
        Start eBPF packet filter
        """
        self.daemon_proc.start()

    def get_log_pipe(self):
        return self.log_pipe


class UmbrellaPKT:
    def __init__(self, ebpf_files, operations=None):
        """
        Initiate of UmbrellaPKT userspace 
        """
        self.ebpf_daemons = dict({})
        self.ebpf_pkt_logs = dict({})
        self.operations = operations    

        pkt_monitor_reload_trigger, pkt_pipe = Pipe()
        self.pkt_monitor_trigger_pipe = pkt_monitor_reload_trigger

        for ebpf_name, ebpf_config in ebpf_files.items():
            try:
                self.ebpf_daemons[ebpf_name] = eBPFPKTDaemon(ebpf_name, ebpf_config)
                if "log" in ebpf_config:
                    ebpf_log = eBPFPKTLog(ebpf_name, ebpf_config["log"])                    
                    self.ebpf_pkt_logs[ebpf_name] = ebpf_log
            except:
                print("Failed to load {}", ebpf_name)
        
        self.pkt_monitor_pipes = []
        self.pkt_monitor_pipes.append(pkt_pipe)
        for ebpf_name, ebpf_daemon in self.ebpf_daemons.items():
            self.pkt_monitor_pipes.append(ebpf_daemon.get_log_pipe())


    def start_all(self):
        """
        Start all eBPF PKT, parallel loading
        Seems like fake concurrent coroutines
        """
        for ebpf_name, ebpf_pkt in self.ebpf_daemons.items():
            ebpf_pkt.start()
            print("{}  starting".format(ebpf_name))

    def pkt_mon_loop(self):
        try:
            while self.pkt_monitor_pipes:
                for pipe in wait(self.pkt_monitor_pipes):
                    try:
                        event_item = pipe.recv()                    
                        pkt_str = str(event_item)
                        pkt = pkt_str[:pkt_str.find("->")].strip()
                        if pkt not in self.ebpf_pkt_logs:
                            print(pkt_str)
                        else:
                            self.ebpf_pkt_logs[pkt].log(pkt_str[pkt_str.find("->")+3:])
                    except BaseException as e:
                        self.pkt_monitor_pipes.remove(pipe)

        except KeyboardInterrupt:
            sys.exit()

    def start_all(self):
        """
        """
        for ebpf_name, ebpf_lsm in self.ebpf_daemons.items():
            ebpf_lsm.start()

        self.pkt_mon_th = threading.Thread(name="pkt_mon", target=self.pkt_mon_loop)
        self.pkt_mon_th.start()
