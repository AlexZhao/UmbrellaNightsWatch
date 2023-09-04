# UmbrellaNightsWatch     

[English](README.md) | 简体中文    

WARNING/CRITICAL: 错误的配置会将用户锁到系统之外    

Umbrealla NightWatch 是一个Linux系统监控守护进程，根据加载eBPF的不同它会收集不同程度系统访问信息     

Umbrealla NightWatch是纵深网络防御系统的主机防御系统设计， 它可以用来控制DMZ主机的安全性可以扩展到    
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
  1. 不再需要混在模式抓包    
  2. 配置只过滤需要的报文          
  3. 轻负载        

# eBPF的可插拔探针， MAC模块， Packet过滤器    

  NightWatch基于BCC实现动态可更改的eBPF框架，主要包括三个主要eBPF类别：    
     1. eBPF 探针             --- prb    
     2. eBPF LSM             --- lsm   
     3. eBPF Packet Filter   --- pkt   
  可动态修改所有的eBPF组件，根据需要加载不同的eBPF模块，动态可配置， NightWatch本身的安全性由     
  um_lsm.py内建的ebpf_shield提供，其保证NightWatch无法被中止，并控制eBPF模块的加载。   

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
   
    "pipes": [                                            // 控制管道，分别对应prb, lsm, pkt组建
        "umbrella_prb_pipe",
        "umbrella_lsm_pipe",
        "umbreall_pkt_pipe"
    ],

    "umbrella_prb": {                                    // Umbreall PRB 探针配置
        "file_prb": {                                    // 文件访问探针 
            "ebpf": "./ebpf/ebpf_prb_file_access.c"      // eBPF 文件路径
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
                        "enp2s0",
                        "wlp1s0" 
                    ]
                },
                {
                    "pkt_parser": "cls_dns_filter",      // eBPF中的 classier 过滤函数 
                    "pkt_type": "classifier",            // TC classifier
                    "interfaces": [                      // 挂载网络接口列表
                        "wlp1s0"
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
        "nw_endpoint": "http://127.0.0.1:8277",          // nw的命令行端点
        "prophet_endpint": "https://192.168.10.250:",    // prophet配置端点
        "prophet_syslog": "192.168.10.250",              // syslog 接口   
        "equipped_lsm": [
            "net_lsm",
            "exec_lsm"
        ],
        "monitored_events": [
            "tcp_init"
        ],
        "process": {
            "quarantin": {
            }
        }
    },

```

Author: Zhao Zhe(Alex)

![Donate](./DONATE.JPG)
![Donate](./DONATE_Z.JPG)
