#!/usr/bin/python
#
# Apache License 2.0
# Copyright Zhao Zhe (Alex)
#
#  Packet filter of NW
#  sockfilter  socket_fd
#  xdpfilter perf_output (xdp_output)
#  attach to interface
#
#  NW runntime modifiable 
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

from multiprocessing import Process, Pipe
from multiprocessing.connection import wait

from pkt.pkt2json import PKT2JSON

from analyst.provider import DataProvider

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

    def __del__(self):
        if self.active_pkt_log_daemon:
            self.active_pkt_log_daemon = False
            self.pkt_log_daemon_th.join()
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
        except BaseException as e:
            """
            
            """

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
        pkt_filter_bpf = BPF(src_file=ebpf_config["ebpf"], cflags=["-fcf-protection"])
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
                        error_msg = "Attach pkt_parser failed {}".format(e)

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
                            perf_th = threading.Thread(name="pkt.{}".format(output_map), target=pkt_perf_output_thread, args=(ebpf_name, pkt_filter_bpf, output_map, child_log_pipe, log_convert_fn, ), daemon=True)
                            perf_th.start()
                            pkt_outputs_threads["perf"][output_map] = perf_th
                        except BaseException as e:
                            print("Start Perf output filter thread failed with exception {}", e)
                    case _:
                        print("Not supported output config {}:{}", output_type, output_map)
    else:
        print("This is a pkt filter without filter out data")

    while True:
        try:
            cmd = con_pipe.recv()
            cmd_json = json.loads(cmd)
            match cmd_json["cmd"]:
                case "list_all_items":
                    result = dict({"cmd_execute_result": "success"})                    
                    con_pipe.send(json.dumps(result))                        
                case "exit":
                    con_pipe.send('''
                    {
                        "cmd_execute_result": "sucess"
                    }
                    ''')
                    return                        
                case _:
                    con_pipe.send("{'cmd_execute_result': 'unknown command'}")
        except KeyboardInterrupt as k:
            """
            Ignore Keyboard interrupt
            """
        except BaseException as e:
            con_pipe.send('''
            {
                "cmd_execute_result": "failed",
                "error": "command not correct format %s"
            }
            ''' % (cmd_json))

class eBPFPKTDaemon:
    def __init__(self, ebpf_name, ebpf_config):
        """
        eBPF Packet Daemon Process
        """
        log_pipe, child_log_pipe = Pipe()
        parent_pipe, child_pipe = Pipe()
        self.con_pipe = parent_pipe
        self.log_pipe = log_pipe
        self.ebpf_name = ebpf_name

        self.daemon_proc = Process(target=pkt_daemon, name=ebpf_name, args=(child_pipe, child_log_pipe, ebpf_name, ebpf_config, ))
        self.active = False

    def __del__(self):
        print("Exit [{}], cleanup environment".format(self.ebpf_name))
        if self.active:
            self.daemon_proc.terminate()
            self.daemon_proc.join()

    def start(self):
        """
        Start eBPF packet filter
        """
        try:
            self.daemon_proc.start()
            res = json.loads(self.con_pipe.recv())
            if res["initialization"] == "finished":
                self.active = True
                return self.active
        except BaseException as e:
            print("Not able to start pkt daemon process ", self.ebpf_name, " exception: ", e)
        
        self.active = False
        self.daemon_proc.terminate()
        self.daemon_proc.join()
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

    def reload(self, ebpf_name, ebpf_config):
        """
        1. create new ebpf instance
        2. remove existed ebpf instance
        3. no break time of the PKT module
        """
        try:
            log_pipe, child_log_pipe = Pipe()
            parent_pipe, child_pipe = Pipe()
            reloaded_daemon_process = Process(target=pkt_daemon, name=ebpf_name, args=(child_pipe, child_log_pipe, ebpf_name, ebpf_config, ))
            reloaded_daemon_process.start()

            initialization_status = parent_pipe.recv()
            status = json.loads(initialization_status)
            if status["initialization"] != "finished":
                return None, {'reload_pkt': 'failed', "pkt": ebpf_name}
        except BaseException as e:
            return None, {'reload_pkt': 'failed', "pkt": ebpf_name}

        try:
            cmd = """
            {
                "cmd": "exit"
            }
            """
            self.con_pipe.send(cmd)
            res = json.loads(self.con_pipe.recv())
            if res["cmd_execute_result"] != "success":
                return None, {'reload_pkt' : 'failed', 'pkt': ebpf_name}
            
            self.daemon_proc.terminate()
            self.daemon_proc.join()
            self.con_pipe.close()
            self.log_pipe.close()
        except BaseException as e:
            return None, {'reload_pkt': 'failed', 'pkt': ebpf_name, 'details': "Exception {}".format(e)}

        self.con_pipe = parent_pipe
        self.log_pipe = log_pipe
        self.daemon_proc = reloaded_daemon_process

        return log_pipe, {'reload_pkt' : 'success', 'pkt': ebpf_name}

    def stop(self):
        try:
            cmd = """
            {
                "cmd": "exit"
            }
            """
            self.con_pipe.send(cmd)
            res = json.loads(self.con_pipe.recv())
            if res["cmd_execute_result"] != "success":
                return None

            self.daemon_proc.terminate()
            self.daemon_proc.join()
            self.con_pipe.close()
            self.log_pipe.close()
        except BaseException as e:
            return None 

        return self.log_pipe

class UmbrellaPKT:
    def __init__(self, ebpf_files, operations=None, events_monitor=None, msg_topics=None):
        """
        Initiate of UmbrellaPKT userspace 
        """
        self.ebpf_daemons = dict({})
        self.ebpf_pkt_logs = dict({})
        self.providers = dict({})

        self.operations = operations    
        self.events_monitor = events_monitor
        self.topics = msg_topics

        pkt_monitor_reload_trigger, pkt_pipe = Pipe()
        self.pkt_monitor_trigger_pipe = pkt_monitor_reload_trigger

        for ebpf_name, ebpf_config in ebpf_files.items():
            try:
                self.ebpf_daemons[ebpf_name] = eBPFPKTDaemon(ebpf_name, ebpf_config)
                self.update_providers(ebpf_name, ebpf_config)
                if "log" in ebpf_config:
                    ebpf_log = eBPFPKTLog(ebpf_name, ebpf_config["log"])                    
                    self.ebpf_pkt_logs[ebpf_name] = ebpf_log
            except:
                print("Failed to load {}", ebpf_name)
        
        self.pkt_monitor_pipes = []
        self.pkt_monitor_pipes.append(pkt_pipe)
        for ebpf_name, ebpf_daemon in self.ebpf_daemons.items():
            self.pkt_monitor_pipes.append(ebpf_daemon.get_log_pipe())

        self.pkt_monitor_active = False

    def set_events_monitor(self, events_monitor):
        self.events_monitor = events_monitor

    def update_providers(self, ebpf_name, ebpf_config):
        if "providers" in ebpf_config:
            if ebpf_name in self.providers:
                self.providers[ebpf_name].update_config(ebpf_config["providers"])
            else:
                self.providers[ebpf_name] = DataProvider(ebpf_name, ebpf_config["providers"])

    def pkt_mon_loop(self):
        while self.pkt_monitor_active:
            for pipe in wait(self.pkt_monitor_pipes):
                try:
                    event_item = pipe.recv()                        
                    pkt_str = str(event_item)
                    pkt = pkt_str[:pkt_str.find("->")].strip()
                        
                    if pkt in self.providers:
                        self.events_monitor.consume_pkt_event(self.providers[pkt].convert(pkt_str[pkt_str.find("->")+3:]))                    

                    if pkt not in self.ebpf_pkt_logs:
                        print(pkt_str)
                    else:
                        self.ebpf_pkt_logs[pkt].log(pkt_str[pkt_str.find("->")+3:])
                except BaseException as e:
                    self.pkt_monitor_pipes.remove(pipe)


    def clean_all(self):
        print("Clean all loaded PKT, overall {} loaded".format(len(self.ebpf_daemons)))
        self.ebpf_daemons.clear()
        self.pkt_monitor_active = False
        self.reload_log_pipe()

    def start_all(self):
        """
        Start all eBPF PKT, parallel loading
        Seems like fake concurrent coroutines
        """
        failed_pkts = [] 
        for ebpf_name, ebpf_pkt in self.ebpf_daemons.items():
            if ebpf_pkt.start():
                print("{}  started".format(ebpf_name))
            else:
                failed_pkts.append(ebpf_name)
        
        for ebpf_name in failed_pkts:
            self.ebpf_daemons.pop(ebpf_name)

        self.pkt_monitor_active = True
        self.pkt_mon_th = threading.Thread(name="pkt_mon", target=self.pkt_mon_loop, daemon=True)
        self.pkt_mon_th.start()

    def list_all(self):
        """
        List all PKT mods
        """
        result = []
        for ebpf_name, ebpf_pkt in self.ebpf_daemons.items():
            result.append(ebpf_name)
        
        return result 

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

    def reload_log_pipe(self):
        self.pkt_monitor_trigger_pipe.send("Refresh log monitor")

    def add_ebpf_pkt(self, new_pkt, ebpf_pkt_config):
        """
        Add eBPF Packet Filter
        """
        if new_pkt not in self.ebpf_daemons:
            self.execute_setup_operation(ebpf_pkt_config)
            new_ebpf_pkt = eBPFPKTDaemon(new_pkt, ebpf_pkt_config)
            self.ebpf_daemons[new_pkt] = new_ebpf_pkt
            self.ebpf_daemons[new_pkt].start()

            self.update_providers(new_pkt, ebpf_pkt_config)

            self.pkt_monitor_pipes.append(new_ebpf_pkt.get_log_pipe())
            self.reload_log_pipe()
            return { 'add_pkt': 'success', "pkt": new_pkt }
        else:
            return { "add_pkt": "failed", "already_existed": new_pkt}       

    def del_ebpf_pkt(self, del_pkt):
        """
        Delete eBPF Packet Filter
        """
        if del_pkt not in self.ebpf_daemons:
            return { 'del_pkt': 'failed', 'pkt': del_pkt}
        else:
            log_pipe = self.ebpf_daemons[del_pkt].stop()
            if log_pipe == None:
                return {'del_pkt': 'failed', 'pkt': del_pkt}
            
            self.ebpf_daemons.pop(del_pkt)
            self.providers.pop(del_pkt)
            return { 'del_pkt': 'success', 'pkt': del_pkt}

    def list_details_of_ebpf(self, ebpf_name):
        if ebpf_name in self.ebpf_daemons:
            return self.ebpf_daemons[ebpf_name].list_all_items()
        else:
            return "{}"
    
    def reload_ebpf_pkt(self, reload_pkt, ebpf_pkt_config):
        """
        Reload already loaded eBPF PKT, runtime update
        """
        if reload_pkt in self.ebpf_daemons:
            log_pipe, res = self.ebpf_daemons[reload_pkt].reload(reload_pkt, ebpf_pkt_config)
            if log_pipe != None:
                self.update_providers(reload_pkt, ebpf_pkt_config)
                self.pkt_monitor_pipes.append(log_pipe)
                self.reload_log_pipe()
                return res
            else:
                return res
        else:
            return {'reload_pkt': "failed", "not_existed": reload_pkt}       