## NightsWatch Basic Architecture Design   
     1. reloadable LSMs    
           a. work already    
     2. reloadable Probes    
     3. reloadable analysis   
     4. reloadable operations   


## Tree based module dependency   



## Events Monitor   

    "pipes": [
        "umbrella_prb_pipe",
        "umbrella_lsm_pipe"
    ],

    "monitor_profiles": {
        "providers": {
            "source_prb_pipe": {
                  "pipe": "umbrella_prb_pipe",
                  "application_file": {
                        "filter": "[file_prb]",
                        "regex": "",
                        "map": {
                              "":"",
                              "":""
                        }
                  },
                  "application_net": {

                  }
            },
            "source_lsm_pipe": {
                  "pipe": "umbrella_lsm_pipe",

            },
            "source_analysis": {
                  "python_mod": ""
            }
        }
    }

    "umbrella_prb": {
        "file_prb": {
            "ebpf": "./ebpf/ebpf_prb_file_access.c",
            
            "consumer": {
                  "pipe": "umbrella_prb_pipe",
                  "filter": "[file_prb]"
            }

        },
        "module_prb": {
            "ebpf": "./ebpf/ebpf_prb_mod_op.c",

            "consumer": {
                  "log": "/var/log/modules.log",
                  "filter": "[module_prb]"
            }
        }
    },

    "umbrella_lsm": {
        "file_lsm": {
            "ebpf": "./ebpf/ebpf_lsm_file.c",

            "consumer": {
                  "pipe": "umbreall_lsm_pipe",
                  "filter": ""
            }
        }
    }

## Analysisor     
   "analysor" : {
      "lsm_config_endpoint": "http://127.0.0.1:8277/lsm",
      
   }
