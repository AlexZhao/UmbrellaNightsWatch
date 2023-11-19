# Apache 2.0
# Copyright Zhao Zhe (Alex)
#
# Builtin User profile analyst
import os
from datetime import datetime

class UserProfile:
    def __init__(self, user, log_path):
        """
        Initialize the Per User Monitoring
        """
        self.user_folder = os.path.join(log_path, user)
        if not os.path.exists(self.user_folder):
            os.mkdir(self.user_folder)

        cdt = datetime.now()

        self.cur_date = "%s-%s-%s" % (cdt.year, cdt.month, cdt.day)        
        log_file = "{}.log".format(self.cur_date)
        self.log_file_path = os.path.join(self.user_folder, log_file)
        self.log_file = open(self.log_file_path, "a")

    def check_update_date(self, time):
        if self.cur_date != time.split()[0]:
            self.cur_date = time.split()[0]
            self.log_file.close()
            log_file = "{}.log".format(self.cur_date)
            self.log_file_path = os.path.join(self.user_folder, log_file)
            self.log_file = open(self.log_file_path, "a")

    def update_execv_access(self, event):
        """
        Update Execv command to monitoring user
        """
        self.check_update_date(event["timestamp"])
        log = "{} : {} -> {}\n".format(event["timestamp"], event["bin"], event["params"])
        self.log_file.write(log)
        self.log_file.flush()


