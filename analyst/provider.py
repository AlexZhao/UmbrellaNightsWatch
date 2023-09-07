# Apache Licence 2.0
# Copyright Zhao Zhe (Alex)
#
# Provider Convert section map to topic's item 
#
import json

class DataProvider:
    def __init__(self, ebpf_name, config):
        self.ebpf_name = ebpf_name
        self.provider_config = config
        self.convert_map = dict({})

        for func_name, topic_config in config.items():
            filter_name = "[{}]:[{}]".format(ebpf_name, func_name)
            self.convert_map[filter_name] = topic_config

    def update_config(self, config):
        for func_name, topic_config in config.items():
            filter_name = "[{}]:[{}]".format(self.ebpf_name, func_name)
            self.convert_map[filter_name] = topic_config
        self.provider_config = config


    def attr_map_sections(self, provider_msg, log_sections, attr):
        if "key" in attr:
            key = attr["key"]
            if "sep" in log_sections:
                provider_msg[key] = attr["sep"].join(log_sections)
            else:
                provider_msg[key] = " ".join(log_sections)

    def map_str_to_json(self, topic, log, map=None):
        if map:
            provider_msg = dict({
                "topic": topic
            })

            try:
                log_sections = []
                splits = log.split("[")
                for part in splits:
                    if len(part) > 0:
                        log_sections.append(part[:part.find("]")])
             
                for section, attr in map.items():
                    ids = section.split(':') 
                    if len(ids) == 1:
                        id = int(section)
                        if id < len(log_sections):
                            if type(attr) is str:
                                provider_msg[attr] = log_sections[id]
                            else:
                                logs = []
                                logs.append(log_sections[id])
                                self.attr_map_sections(provider_msg, logs, attr)
                    elif len(ids) == 2:
                        if ids[0] == '':
                            id_1 = 0
                        else:
                            id_1 = int(ids[0])
                        if ids[1] == '':
                            id_2 = len(log_sections) - 1
                        else:
                            id_2 = int(ids[1])
                        logs = []
                        for i in range(id_1, id_2):
                            if i < len(log_sections):
                                logs.append(log_sections[i])
                        if type(attr) is str:
                            provider_msg[attr] = " ".join(logs)
                        else:
                            self.attr_map_sections(provider_msg, logs, attr)
            except BaseException as e:
                print("Not able to processing the convertion ", e, " content  ", log)
            
            return json.dumps(provider_msg)
        else:
            provider_msg = dict({
                "topic": topic,
                "orig_txt": log
            })
            return json.dumps(provider_msg)

    def convert(self, log):
        """
        Convert log to json event based on Data Provider configuration
        """
        provider_key = log[:log.find(":", log.find(":")+1)]
        if provider_key in self.convert_map:
            if "topic" in self.convert_map[provider_key]:
                if "map" in self.convert_map[provider_key]:
                    return self.map_str_to_json(self.convert_map[provider_key]["topic"], log, self.convert_map[provider_key]["map"])
                else:
                    return self.map_str_to_json(self.convert_map[provider_key]["topic"], log)
        else:
            return None