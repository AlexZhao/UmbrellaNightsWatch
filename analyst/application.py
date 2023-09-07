# Apache 2.0
# Copyright Zhao Zhe (Alex)
#
from pygtrie import StringTrie

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
        self.file_record_pattern = StringTrie(separator="/")
        
        # recording each created process instance alive period
        self.pids = dict({})

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

    def update_file_access(self, event):
        """
        Update file access by process
        """
        if "file" in event:
            file_loc = self.need_record_full_file(event["file"])
            if self.file_access.has_key(file_loc):
                self.file_access[file_loc] = self.file_access[file_loc] + 1
            else:
                self.file_access[file_loc] = 1

    def update_net_access(self, event):
        """
        """
        if "type" in event:
            type_of_con = event["type"]
            if type_of_con in self.net_access:
                target_ip = event["target_ip"]
                if target_ip in self.net_access[type_of_con]:
                    self.net_access[type_of_con][target_ip] = self.net_access[type_of_con][target_ip] + 1
                else:
                    self.net_access[type_of_con][target_ip] = 1

    def update_dev_access(self, event):
        """
        """
        print(event)


    def update_execv_access(self, event):
        if "bin" in event and "params" in event:
            bin = event["bin"]
            cmdline = event["params"]
            if bin in self.execv_cmd:
                if cmdline in self.execv_cmd[bin]:
                    self.execv_cmd[bin][cmdline] = self.execv_cmd[bin][cmdline] + 1
                else:
                    self.execv_cmd[bin][cmdline] = 1
            else:
                self.execv_cmd[bin] = dict({cmdline: 1})

    def update_seldom_syscall(self, event):
        """
        """
        if "syscall" in event:
            syscall = event["syscall"]
            if syscall in self.seldom_syscall:
                self.seldom_syscall[syscall] = self.seldom_syscall[syscall] + 1
            else:
                self.seldom_syscall[syscall] = 1

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
