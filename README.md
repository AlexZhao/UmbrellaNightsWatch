# UmbrellaNightsWatch   

NightsWatch is a toy Linux System monitoring daemon process which will record everything of the system accessed      

It is in the core of Defense in Depth of Umbrella design, it used to control the DMZ security overall      

## Process Level Monitoring this is the last layer to direct enhance os    
    This used for DMZ device to monitor itself's connectivities
    and all the activities on the DMZ host 

    not like telescope and firewall is based on control connected devices network behavior         

    The inner layer of defense in depth, after root system still have roadblock   

### Monitoring Fork/execv shellcode    

### Monitoring kill and signals and closely mon critical application restart    

### Monitoring specific file be opened and closed    
    e.g.
          /etc/shadow
          ...

### Monitoring bootup kernel version and configuration    
    

### Monitor which process initiate what connection from DMZ    
    DMZ works as server host, it initiates out traffic only for proxy and DNS bridge       



### XDP packet capture     
  tcpdump works well why not     
  1. non promiscuous mode capture packet (direct device driver, NIC card level mode will receive many not dested packet to the host)   
  2. better configurable filter to only hook out interesting packets     
  3. it is not about performance, it is about to not impact on existing working mode but to hookout required stuffs for analysis    

### Firefox    
   1. DNS Resolver threads detect many IP not works as DNS server    

   use executable file short name as the filter    

### A basic workable milestone for controlling per application network access   
   1. config application firefox under control access list   
   curl -X POST -d "cmd=update_config" -d "map=app_ipv4_strict_access_list" -d "key=firefox" -d "key_convert=str2taskinfo" -d "value=ipv4_allow_list" -d "value_convert=str2mapfd" http://127.0.0.1:8277/lsm/basic_lsm     

   2. add allowed access ip   
   curl -X POST -d "cmd=update_config" -d "map=ipv4_allow_list" -d "key=192.168.10.1" -d "key_convert=str2ip" -d "value=1" -d "value_convert=str2int" http://127.0.0.1:8277/lsm/basic_lsm    

   3. add new eBPF 
   curl -X POST -d "cmd=add_ebpf_lsm" -d "lsm=file_lsm" -d "config=./conf/file_lsm.conf" http://127.0.0.1:8277/lsm

   4. replace eBPF 
   curl -X POST -d "cmd=reload_ebpf_lsm" -d "config=./config/file_lsm.conf" http://127.0.0.1:8277/lsm/file_lsm


### The design based on ideas   
  1. no need to know what dependency lib can be trusted or not    
  2. only check the application runtime behavior no matter what types of lib it is used    
  3. reject all its not should initiated behaviors based on analysis   

### Basic Architecture Design   

              NW (NightsWatch) (restful API endpoints) <---|   
               |                                           |
               -------------- Events Monitor ---|          |
               |                                |          |
               -------------- Analyst   <-------|          |
               |                |                          |
               |                ---------------------------|
               |-------------- LSM 
                                
                                

### LD_AUDIT  module  used to track the dynamic linked process   
     1. record well known so functionalities and its function    
     2. track the possible breach of the share lib be hooked out   

    
## TODO Priority   
  1. Basic nw_cli     
  2. um_prb refactory    
  3. support cgroups and namespace nsproxy       
  4. containerd listening at empheral port without bind  quite weird behavior    
  5. quarantine_app nw_cli (quarantine level is configurable)


Author: Zhao Zhe(Alex)
