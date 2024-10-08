# UmbrellaNightsWatch     

[English](README.md) | 简体中文    

WARNING/CRITICAL: 错误的配置会将用户锁到系统之外    

Umbrealla NightWatch 是一个Linux系统监控守护进程，根据加载eBPF的不同它会收集不同程度系统访问信息     
粒度和范围可以根据配置文件来进行调整   

Umbrealla NightWatch是纵深网络防御系统的主机防御系统设计， 它可以用来控制DMZ主机的安全性， 并可以扩展到    
Linux内和中的多种不同安全层级加固。    

# 纵深网络防御       

纵深网络防御是一个关于网络和系统安全设计的基本概念，它基于多重层次组成的防线和点构成的安全加强和控制，从而在整体上
增强整个网络节点的安全性。
纵深网络防御基于每个系统都会存在已知和未知的安全威胁，不同的系统中所含有的安全威胁各不相同，而不同系统混合使用在某些方面
可以作为特性加强整个系统的安全性，减少整个系统被网络攻击穿透的可能。

# 进程监控来加固操作系统安全性     

    NightWatch用来对DMZ设备上的所有行为进行监控，识别威胁并终止威胁   
    NightWatch工作在纵深网络防御的内圈,用来保护系统不被渗透探测和恶意使用      

## 监控系统中的进程和线程状态切换       

## 监控系统中应用程序发起的文件访问和磁盘挂在操作       
    e.g.
          /etc/shadow
          ...

## 监控系统中的配置更改       
    
## 监控所有的用户态应用程序发起的网络连接        

## 监控所有用户台程序的系统调用模式    

## 网络报文检测         
  NightWatch使用eBPF来对XDP和TC进行报文检测，主要基于下面的考虑     
  1. 不再需要混杂模式抓包    
  2. 配置只过滤需要的报文          
  3. 轻负载

## XDP防火墙              
  NightWatch的pkt系统可以用来实现基于zone的XDP防火墙    
  和netfilter/iptable防火墙对比的优点：
    1. XDP可以在报文从网卡收到没有经过协议栈处理时进行丢包控制    
    2. 可以绕过所有的协议栈网络协议报文处理    


# eBPF的可插拔探针， MAC模块， Packet过滤器/防火墙        
  NightWatch基于BCC实现动态可更改的eBPF框架，主要包括三个主要eBPF类别：    
     1. eBPF 探针             --- prb    
     2. eBPF LSM             --- lsm   
     3. eBPF Packet Filter   --- pkt   
  可动态修改所有的eBPF组件，根据需要加载不同的eBPF模块，动态可配置。    
  
  NightWatch本身的安全性由um_lsm.py内建的ebpf_shield提供，其保证NightWatch无法被中止，并控制eBPF模块的加载。   
  ebpf_shield使用BPF_LSM来控制对NightWatch用户态进程的修改   

## eBPF PRB    
     dev_prb      - ebpf_prb_dev.c    
     file_prb     - ebpf_prb_file.c    
     mod_op_prb   - ebpf_mod_op.c   

## eBPF LSM   
     bpf_lsm      - ebpf_lsm_bpf.c    
     exec_lsm     - ebpf_lsm_exec.c    
     file_lsm     - ebpf_lsm_file.c    
     inode_lsm    - ebpf_lsm_inode.c    
     ipc_lsm      - ebpf_lsm_ipc.c    
     key_lsm      - ebpf_lsm_key.c    
     kmod_lsm     - ebpf_lsm_kmod.c    
     mount_lsm    - ebpf_lsm_mount.c   
     net_lsm      - ebpf_lsm_net.c   
     netlink_lsm  - ebpf_lsm_netlink.c    
     path_lsm     - ebpf_lsm_path.c    
     task_lsm     - ebpf_lsm_task.c    
     time_lsm     - ebpf_lsm_time.c    
     uring_lsm    - ebpf_lsm_uring.c   
     xfrm_lsm     - ebpf_lsm_xfrm.c   
     
## eBPF PKT   
     dns_pkt      - ebpf_pkt_dns.c    
     dhcp_pkt     - ebpf_pkt_dhcp.c    

# Umbrella NightWatch 配置文件    
```
{
    "audit_log_path" : "/var/log/nw.log",
    "audit_log_enabled" : true, 

    "topics": {                                         // 消息topics，提供给analyst分析使用的topic定义,消息为json格式
        "file_open" : {
            "app":"str",
            "pid":"int",
            "file":"str",
            "timestamp":"str"
        },
        ...
    }

    "umbrella_prb": {                                    // Umbreall PRB 探针配置
        "file_prb": {                                    // 文件访问探针 
            "ebpf": "./ebpf/ebpf_prb_file_access.c"      // eBPF 文件路径
            "providers": {                               // file_prb作为消息provider
                "sys_enter_open": {                      // eBPF 监控函数
                    "topic": "file_open"                 // 次监控函数提供的 消息 topic,使用default映射
                },
                "sys_enter_openat": {
                    "topic": "file_open",
                    "map": {                             // 消息监控msg 翻译为 消息topic的对应方法
                        "2": "timestamp",                // 
                        "3": "app",                      //  
                        "4": "pid",                      // 
                        "5": "file"                      // 
                    }
                },
                "sys_enter_openat2": {
                    "topic": "file_open"
                }
            }
        },
        "module_prb": {                                  // 模块加载探针
            "ebpf": "./ebpf/ebpf_prb_mod_op.c"           // eBPF 文件路径
        }
    },

    "umbrella_pkt": {                                    // Umbrella PKT 报文过滤 
        "dns_pkt": {                                     // DNS过滤器
            "ebpf": "./ebpf/ebpf_pkt_dns.c",             // eBPF 路径
            "pkt_parsers": [                             // 过滤器列表
                {
                    "pkt_parser": "xdp_dns_filter",      // eBPF中的 XDP 过滤函数
                    "pkt_type": "xdp",                   // XDP
                    "interfaces": [                      // 挂载网络接口列表    
                        "lo",
                        "eth0",
                        "wlan0" 
                    ]
                },
                {
                    "pkt_parser": "cls_dns_filter",      // eBPF中的 classier 过滤函数 
                    "pkt_type": "classifier",            // TC classifier
                    "interfaces": [                      // 挂载网络接口列表
                        "wlan0"
                    ]
                }
            ],
            "pkt_outputs": [                             // 输出perf 
                {"perf_output": "pkts"}
            ],
            "log": {                                     // 记录报文到 log 
                "file": "/var/log/nw_dns_pkt.log",       // 抓包文件   
                "flush_threshold": 1
            }
        }
    },

    "umbrella_lsm": {                                    // Umbrealla LSM MAC规则配置
        "net_lsm": {                                     // 网络访问MAC规则
            "ebpf": "./ebpf/ebpf_lsm_net.c",             // 
        },
        ...                                              // 具体配置
    },

    "analyst": {                                         // 实时分析器配置   
        "nw_endpoint": "http://127.0.0.1:8277",          // NW的控制命令接口
        
        "app_profile": {                                 // 内置的app_profile分析器
            "consumers": { 
                "net_connect": "update_net_access",      // 分析器订阅的消息topics， 和update此消息所使用的内部接口
                "file_open": "update_file_access",
                "dev_operate": "update_dev_access",
                "execv": "update_execv_access",
                "seldom_syscall": "update_seldom_syscall"
            },
            "file_access_ignore_patterns": {
                "/home": 4,
                "/var/tmp": 5,
                "/var/log": 5,
                "/var/cache": 5,
                "/tmp": 3,
                "/dev/shm": 4,
                "/usr/share": 4,
                "/usr/local/share": 5
            }
        },

        "prophet_analysis": {
            "prophet_endpint": "https://192.168.10.250:",
            "prophet_syslog": "192.168.10.250",
            "consumers": {
                "net_connect": "analysis_net_access"
            }
        }
    }
}

实时分析器使用的 provider -> topic -> consumer 语法

例如：
    "topics": {                                  
        "file_open" : {
            "app":"str",
            "pid":"int",
            "file":"str",
            "timestamp":"str"
        },
        ...
    }

    "umbrella_prb": {                                    
        "file_prb": {                                     
            "ebpf": "./ebpf/ebpf_prb_file_access.c"      
            "providers": {                               
                "sys_enter_openat": {
                    "topic": "file_open",
                    "map": {                            
                        "2": "timestamp",                
                        "3": "app",                     
                        "4": "pid",                   
                        "5": "file"                
                    }
                }
            }
        }
        ...
    }

    "app_profile": {                                 
        "consumers": { 
            "net_connect": "update_net_access",      
            "file_open": "update_file_access",
            ...
        }
    }

provider将文本生成json消息

    sys_enter_openat prb函数的文本格式消息为
    [   0    ] [        1       ] [      2      ]  [     3    ] [  4  ] [           5             ] 
    [file_prb]:[sys_enter_openat]:[?-?-? ?:?:?.?]  [python3.11] [32073] [include/linux/...........]
    
    根据 "map"的定义 此 消息会 生成json格式的 topic
    {
        "topic":"file_open",
        "app": "python3.11",
        "pid": 32073,
        "file":"include/linux/........",
        "timestamp":"?-?-? ?:?:?.?"
    }

    此语法还支持例如：
    "3:": {
        "key": "params",
        "sep": " "
    }
    对上面的sys_enter_openat的文本会展开为
    {
        ...
        "params": "python3.11 32073 include/linux/.....",  表示从第3个item使用空格连接展开为key params的对应消息
        ...
    }

consumer将json消息使用内建的函数更新:
    "app_profile": {                                 
        "consumers": { 
            "net_connect": "update_net_access",      
            "file_open": "update_file_access",
            ...
        }
    }
    topic  "file_open"  对应 app_profile配置的分析器 内置method update_file_access来使用 file_open topic的数据    


```

Author: Zhao Zhe(Alex)
