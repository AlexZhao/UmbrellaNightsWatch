#!/usr/bin/python
#
# Apache Licence 2.0
# Copyright Zhao Zhe (Alex)
#
#  Analyst for data analysis called by Monitor
#
#  consume data from EventMonitor (collected from probes)
#  initiate reaction to UmLsm
import json

from pygtrie import StringTrie
from threading import Lock

from analyst.application import ApplicationProfile

class AppProfileAnalyst:
    def __init__(self, config):
        """
        Profile specific analyst
        """
        self.dispachers = dict({})
        if "consumers" in config:
            for key, val in config["consumers"].items():
                self.dispachers[key] = val

        self.monitored_apps_lock = Lock()
        self.monitored_apps = dict({})

        self.file_access_ignore_patterns = StringTrie(separator="/")

        if "file_access_ignore_patterns" in config:
            for key, val in config["file_access_ignore_patterns"].items():
                self.file_access_ignore_patterns[key] = val

    def update(self, topic, event):
        """
        Per topic update the events to App Profile monitoring
        """
        if topic in self.dispachers:
            app_name = None
            if "app" in event:
                self.monitored_apps_lock.acquire()
                if not event["app"] in self.monitored_apps:
                    self.monitored_apps[event["app"]] = ApplicationProfile(event["app"])
                self.monitored_apps_lock.release()
                app_name = event["app"]

            match self.dispachers[topic]:
                case "update_net_access":
                    self.update_net_access(app_name, event)
                case "update_file_access":
                    self.update_file_access(app_name, event)
                case "update_dev_access":
                    self.update_dev_access(app_name, event)
                case "update_execv_access":
                    self.update_execv_access(app_name, event)
                case "update_seldom_syscall":
                    self.update_seldom_syscall(app_name, event)                    

    def need_record_full_file(self, file_loc):
        key, val = self.file_access_ignore_patterns.longest_prefix(file_loc)
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

    def update_net_access(self, app_name, event):
        try:
            """
            """
            if app_name:
                self.monitored_apps[app_name].update_net_access(event)                
        except BaseException as e:
            """
            """

    def update_file_access(self, app_name, event):
        try:
            if app_name:
                if "file" in event:
                    file_loc = self.need_record_full_file(event["file"])
                    event["file"] = file_loc
                self.monitored_apps[app_name].update_file_access(event)
        except BaseException as e:
            """
            """

    def update_dev_access(self, app_name, event):
        try:
            if app_name:
                self.monitored_apps[app_name].update_dev_access(event)
        except BaseException as e:
            """
            """

    def update_execv_access(self, app_name, event):
        try:
            if app_name:
                self.monitored_apps[app_name].update_execv_access(event)
        except BaseException as e:
            """
            """

    def update_seldom_syscall(self, app_name, event):
        try:
            if app_name:
                self.monitored_apps[app_name].update_seldom_syscall(event)
        except BaseException as e:
            """
            """

    def dump_app_details(self, app):
        if app in self.monitored_apps:
            return self.monitored_apps[app].dump_app_profile()
        else:
            return {'result': "failed", "details": "Under Impl"}

    def list_apps(self):
        details = []
        self.monitored_apps_lock.acquire()
        for app, _ in self.monitored_apps.items():
            details.append(app)
        self.monitored_apps_lock.release()
        return {'result': "success", "details": details}

    def list_dev_access(self):
        return {'result': "failed", "details": "Under Impl"}

class ProphetAnalyst:
    def __init__(self, config):
        """
        Prophet Analyst 
        """


    def update(self, topic, event):
        """
        Per topic update the events to Prophet 
        """

class Analyst:
    def __init__(self, config, topics):
        """
        Analyst
        """
        self.debug = False
        self.topics = topics
        self.app_profile = None
        self.prophet_analysis = None

        self.consumer_topics = dict({})

        if "app_profile" in config:
            self.app_profile = AppProfileAnalyst(config["app_profile"])
            for topic, _ in config["app_profile"]["consumers"].items():
                if topic in self.consumer_topics:
                    self.consumer_topics[topic].append(self.app_profile)
                else:
                    self.consumer_topics[topic] = []
                    self.consumer_topics[topic].append(self.app_profile)

        if "prophet_analysis" in config:
            self.prophet_analysis = ProphetAnalyst(config["prophet_analysis"])
            for topic, _ in config["app_profile"]["consumers"].items():
                if topic in self.consumer_topics:
                    self.consumer_topics[topic].append(self.app_profile)
                else:
                    self.consumer_topics[topic] = []
                    self.consumer_topics[topic].append(self.app_profile)

    def get_app_profile(self):
        return self.app_profile

    def get_prophet_analysis(self):
        return self.prophet_analysis

    def consume(self, event=None):
        """
        Consume nw monitored events
        1. analysis by Analyst module for simple reaction
        2. push for prophet for take reaction
        """
        try:
            if event:
                json_event = json.loads(event)
                if json_event["topic"] in self.consumer_topics:
                    for analysis in self.consumer_topics[json_event["topic"]]:
                        analysis.update(json_event["topic"], json_event)
        except BaseException as e:
            print("Exception {} when consume event {}", e, event)