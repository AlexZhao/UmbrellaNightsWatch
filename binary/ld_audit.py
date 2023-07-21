#!/usr/bin/python3
# Copyright Alex Zhao
# ld-linux dynamic loader bindings
# check the function comes from which shared lib
# dynamic linking time injection check
import inotify.adapters
import threading
import sys
import os

class DynamicLinkingAudit:
    def __init__(self, config):
        self.log_path = "/var/log/ld-linux"
        if "log_path" in config:
            self.log_path = config["log_path"]
        
    def start_mon_ld_log(self):
        """
        Use inode notify to monitor audit folder
        """
        self.ld_th = threading.Thread(name="ld audit", target=self.dynamic_link_audit)
        self.ld_th.start()

    def dynamic_linking_record_analysis(self, filename):
        """
        Locate elf loading/binding symbols from which so
        """
        return False

    def close_linking_record(self, filename):
        try:
            os.remove(filename)
        except OSError as e:
            print("close linking record failed {}  {}".format(filename, e.strerror))

    def dynamic_link_audit(self):

        def filter_file_write_close(type_name, e):
            if type_name == 'IN_CLOSE_WRITE':
                return True
            else:
                return False

        ld_linux_folder = inotify.adapters.Inotify()
        ld_linux_folder.add_watch(self.log_path)

        while True:
            try:

                for event in ld_linux_folder.event_gen(yield_nones=False, filter_predicate=filter_file_write_close):
                    (item, type_names, path, filename) = event
                    if self.dynamic_linking_record_analysis("{}/{}".format(path, filename)):
                        print("[{}]  [{}]  [{}]  [{}]".format(item, type_names, path, filename))
                    else:
                        self.close_linking_record("{}/{}".format(path, filename))

            except KeyboardInterrupt:
                sys.exit()