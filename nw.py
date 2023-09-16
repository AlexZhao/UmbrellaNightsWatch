#!/usr/bin/python
#
# Apache License 2.0
# Copyright Zhao Zhe(Alex)
#
# Runtime Network and Application Behavior Monitoring on DMZ
# 
# Umbrealla NW
#
#   with Umbrella Firewall
#        Umbrella Agent
#        Umbrella Telescope
#
#   To works as a basic design of DiD (Defense in Depth)
#
# Umbrella NW based on eBPF to interactive with Linux kernel  
#
#   PRB  -  eBPF Probers
#   LSM  -  eBPF LSM MACs
#   PKT  -  eBPF Packet Filters
#
import sys
import os
import time
import json
from datetime import datetime

from lsm.um_lsm import UmbrellaLSM
from prb.um_prb import UmbrellaPRB
from pkt.um_pkt import UmbrellaPKT

from analyst.analyst import Analyst
from binary.ld_audit import DynamicLinkingAudit
from operations.operation import NWOperations

from multiprocessing import Pipe
from multiprocessing.connection import wait

from flask import Flask, request
from flask_restful import reqparse, Resource, Api

from topics.topics import Topics

class EventsMonitor:
    """
    Events Monitor is the main daemon process to tracking all loaded eBPF subsystems including:
        eBPF probes
        eBPF LSM MACs
        eBPF Packet Filters
    Also it provides the interface to attach analysis module
    EventsMonitor Bridge the communication across eBPF functions and its associated analyst
    functions by communication channel    
    """
    
    def __init__(self):
        self.debug = False
        # audit log is recording all the activities happend to NW itself
        self.audit_log_path = "/var/log/runtime_mon.log"
        self.audit_file = open(self.audit_log_path, "a")
        # NW configuration
        self.config_file = ""
        self.config = dict({})

        # Topics
        self.msg_topics = None

        # PRB, LSM, PKT moduels
        self.prb = None
        self.lsm = None
        self.pkt = None

        # Analyst engine
        self.analyst = None

        # Operation engine
        self.operations = NWOperations()

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

    def set_prb_controller(self, prb):
        self.prb = prb

    def get_prb_controller(self):
        return self.prb

    def set_lsm_controller(self, lsm):
        self.lsm = lsm

    def get_lsm_controller(self):
        return self.lsm

    def set_pkt_controller(self, pkt):
        self.pkt = pkt

    def get_pkt_controller(self):
        return self.pkt

    def set_analyst_engine(self, analyst):
        self.analyst = analyst
    
    def get_analyst_engine(self):
        return self.analyst

    def set_msg_topics(self, topics):
        self.msg_topics = topics

    def get_msg_topics(self):
        return self.msg_topics

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

    def is_pkt_active(self):
        if self.pkt != None:
            return True
        else:
            return False
    
    def consume_prb_event(self, log):
        """
        Events Monitor hook to parse um_prb received events from eBPF prb
        """
        try:
            if self.analyst:
                self.analyst.consume(log)
        except BaseException as e:
            print("Exception {} during parse PRB log {}".format(e, log))

    def consume_lsm_event(self, log):
        """
        Events Monitor hook to parse um_lsm received events from eBPF lsm
        """
        try:
            if self.analyst:
                self.analyst.consume(log)
        except BaseException as e:
            print("Exception {} during parse LSM log {}".format(e, log))

    def consume_pkt_event(self, log):
        """
        Events Monitor hook to parse um_pkt received events from eBPF pkt
        """
        try:
            if self.analyst:
                self.analyst.consume(log)
        except BaseException as e:
            print("Exception {} during parse PKT packet capture {}".format(e, log))

    def close_log(self):
        self.audit_file.close()

    def clean_all(self):
        if self.lsm:
            self.lsm.clean_all()

        if self.prb:
            self.prb.clean_all()

        if self.pkt:
            self.pkt.clean_all()


events_monitor = EventsMonitor()

parser = reqparse.RequestParser()
parser.add_argument('proc', type=str, location='args')

class DumpMonDetails(Resource):
    def get(self):
        return {'usage': "POST to dump monitoring details of process"}
    def post(self):
        """
        POST dump monitoring details
        """
        if events_monitor.get_analyst_engine().get_app_profile():
            app = parser.parse_args()["proc"]
            if app:
                details = events_monitor.get_analyst_engine().get_app_profile().dump_app_details(app)
                return {'result': "success", "details": details}
            else:
                return {'result': "failed", "details": "Not correct URI request parameters proc= required"}
        else:
            return {'result': "failed", "details": "Not correct configured analyst, required to configure app_profile"}

class ListMonProc(Resource):
    def get(self):
        """
        GET to list all process under monitor
        """
        if events_monitor.get_analyst_engine().get_app_profile():
            return events_monitor.get_analyst_engine().get_app_profile().list_apps()
        else:
            return {'result': "failed", "details": "Not correct configured analyst, required to configure app_profile"}

class ListDevAccess(Resource):
    def get(self):
        """
        Get to list all device access direct by applciation on host
        """
        if events_monitor.get_analyst_engine.get_app_profile():
            return events_monitor.get_analyst_engine().get_app_profile().list_dev_access()
        else:
            return {'result': "failed", "details": "Not correct configured analyst, required to configure app_profile"}

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

class PKT(Resource):
    def get(self):
        """
        Check is PKT supported under RuntimeMonitor
        """
        if events_monitor.is_pkt_active():
            result = events_monitor.get_pkt_controller().list_all()
            return {'result': 'success', 'details': result}
        else:
            return {'result': 'success', 'details': 'NO LSM activate'}
    def post(self):
        """
        Post to add/del PKT packet filter modules 
        TODO add/delete operation need to recorded
        """
        command = request.form['cmd']
        match command:
            case "add_ebpf_pkt":
                try:
                    new_pkt = request.form['pkt']
                    if "config" in request.form:
                        config_file = request.form['config']
                    else:
                        config_file = events_monitor.get_config_file()
                        
                    config_content = open(config_file)
                    config = json.load(config_content)
    
                    if "umbrella_pkt" in config:
                        pkt_config = config["umbrella_pkt"]
                    else:
                        pkt_config = config      

                    if new_pkt in pkt_config:
                        ebpf_pkt_config = pkt_config[new_pkt]
                    else:
                        return {'result': 'failed', 'details': 'addd_pkt, no configuration existed for {}'.format(new_pkt)}

                    result = events_monitor.get_pkt_controller().add_ebpf_pkt(new_pkt, ebpf_pkt_config)
                    events_monitor.record_audit_log("add_ebpf_pkt : {}  [{}]".format(new_pkt, ebpf_pkt_config))
                    return result
                except BaseException as e:
                    return {'result': 'failed', 'details': 'add_pkt, not correct command format {}'.format(e)}
            case "del_ebpf_pkt":
                try:
                    del_pkt = request.form['pkt']
                    result = events_monitor.get_pkt_controller().del_ebpf_pkt(del_pkt)
                    events_monitor.record_audit_log("add_ebpf_pkt : {} ".format(del_pkt))
                    return result
                except BaseException as e:
                    return {'result': 'failed', 'details': 'del_pkt, not correct command format {}'.format(e)}
            case _:
                return {'result': 'failed', 'details': "Not supported command {}".format(command)}

class PKTOp(Resource):
    def get(self, pkt_ebpf):
        """
        Check PKT status
        """
        if events_monitor.is_pkt_active():
            result = events_monitor.get_pkt_controller().list_details_of_ebpf(pkt_ebpf)
            return {'result': 'success', 'details': result}
        else:
            return {'result': 'failed', 'details': 'PKT not activate'}
    def post(self, pkt_ebpf):
        """
        Config PKT
        """
        if events_monitor.is_pkt_active():
            command = request.form['cmd']
            match command:
                case "reload_ebpf_pkt":
                    try:
                        if "config" in request.form:
                            config_file = request.form['config']
                        else:
                            config_file = events_monitor.get_config_file()

                        config_content = open(config_file)
                        config = json.load(config_content)

                        if "umbrella_pkt" in config:
                            pkt_config = config["umbrella_pkt"]
                        else:
                            pkt_config = config
                    
                        if pkt_ebpf in pkt_config:
                            ebpf_pkt_config = pkt_config[pkt_ebpf]
                        else:
                            return {'result':'failed', 'details': 'reload_pkt, no configuration existed for {}'.format(pkt_ebpf)}
                    
                        result = events_monitor.get_pkt_controller().reload_ebpf_pkt(pkt_ebpf, ebpf_pkt_config)
                        events_monitor.record_audit_log("reload_ebpf_pkt: {} [{}]".format(pkt_ebpf, ebpf_pkt_config))
                        return result
                    except BaseException as e:
                        return {'result':'failed', 'details': 'reload_pkt, not correct command format {}'.format(e)}
                case _: 
                    return {'result': 'failed', 'details': "Not supported command {}".format(command)}
        else:
            return {'result':'failed', 'details': 'PKT not activate'}

app = Flask(__name__)
api = Api(app)

# Msg topics related update

# Analyst related URI endpoint for commandline interface
api.add_resource(DumpMonDetails, '/dump_mon')
api.add_resource(ListMonProc, '/list_mon')
api.add_resource(ListDevAccess, '/list_dev_access')

# Dynamic modifiable LSM 
api.add_resource(LSM, '/lsm')
api.add_resource(LSMOp, '/lsm/<string:lsm_ebpf>')

# Dynamic modifiable PRB
api.add_resource(PRB, '/prb')
api.add_resource(PRBOp, '/prb/<string:prb_ebpf>')

# Dynamic modifiable PKT
api.add_resource(PKT, '/pkt')
api.add_resource(PKTOp, '/pkt/<string:pkt_ebpf>')

if __name__ == '__main__':
    sched_params = os.sched_param(os.sched_get_priority_max(os.SCHED_RR))
    os.sched_setscheduler(0, os.SCHED_RR, sched_params)

    config_file_path = "./conf/runtime_mon.conf"
    if len(sys.argv) == 2 and sys.argv[1]:
        config_file_path = sys.argv[1]
    
    config_file = open(config_file_path)

    config = json.load(config_file)

    config_file.close()

    # Log used for context analysis without statistics
    if "audit_log_path" in config:
        events_monitor.update_audit_log_path(config["audit_log_path"])
    
    if "audit_log_enabled" in config:
        events_monitor.update_audit_log_enabled(config["audit_log_enabled"])

    events_monitor.set_config(config_file_path, config)

    # used by runtime mon to trace back to only allow runtime_mon use BPF interface
    # for eBPF security reason.
    runtime_mon_pid = os.getppid()
    
    if "bpf_lsm" in config["umbrella_lsm"]:
        print("NW PID {}".format(runtime_mon_pid))
        config["umbrella_lsm"]["bpf_lsm"]["runtime_mon_pid"] = runtime_mon_pid

    nw_operations = NWOperations()

    if "topics" in config:
        msg_topics = Topics(config["topics"])
    else:
        msg_topics = Topics([])
    events_monitor.set_msg_topics(msg_topics)

    if "analyst" in config:
        analyst_engine = Analyst(config["analyst"], events_monitor.get_msg_topics())
        events_monitor.set_analyst_engine(analyst_engine)
    else:
        print("No Analyst Equipped, only record Linux events")

    # eBPF Probes application behavior monitoring
    if "umbrella_prb" in config:
        um_prb_daemon = UmbrellaPRB(config["umbrella_prb"], nw_operations, events_monitor, events_monitor.get_msg_topics())
    else:
        um_prb_daemon = UmbrellaPRB(dict({}), nw_operations, events_monitor, events_monitor.get_msg_topics())
    um_prb_daemon.start_all()
    events_monitor.set_prb_controller(um_prb_daemon)

    # eBPF LSM MAC
    if "umbrella_lsm" in config:
        um_lsm_daemon = UmbrellaLSM(config["umbrella_lsm"], nw_operations, events_monitor, events_monitor.get_msg_topics())
    else:
        um_lsm_daemon = UmbrellaLSM(dict({}), nw_operations, events_monitor, events_monitor.get_msg_topics())
    um_lsm_daemon.start_all()
    events_monitor.set_lsm_controller(um_lsm_daemon)

    # eBPF Packet filter to replace tcpdump, hook on egress TC and ingress XDP
    if "umbrella_pkt" in config:
        um_pkt_daemon = UmbrellaPKT(config["umbrella_pkt"], nw_operations, events_monitor, events_monitor.get_msg_topics())
    else:
        um_pkt_daemon = UmbrellaPKT(dict({}), nw_operations, events_monitor, events_monitor.get_msg_topics())
    um_pkt_daemon.start_all()
    events_monitor.set_pkt_controller(um_pkt_daemon)

    ld_audit_daemon = DynamicLinkingAudit(config["ld_bindings_audit"])
    ld_audit_daemon.start_mon_ld_log()

    # Port Short for RuntimeMonitor RM in ASCII
    app.run(debug=False, port=8277)

    try:
        while True:
            time.sleep(100)
    except KeyboardInterrupt:
        events_monitor.clean_all()
        sys.exit()
