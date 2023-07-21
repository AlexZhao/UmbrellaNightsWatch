## Security not only can based on the executable file name    
    1. executable name can be modified    
    2. use its linked shared lib and bindings functions to check what is real contents of the executable   
    3. static linked executable direct monitor its syscall   

## Track unix socket and its network connectivity flow    
    1. to avoid malware has relay based behavior to handover across traffic based on multiple process handover to workaround behavior analysis    
    2. 

## All not used modules to removed when nw initialized   
    1. when nw bootup it automatic remove all modules which not active   
    2. monitor all modules loading/unloading    
    3. use LSM to reject loading/unloading modules   


## Basic mutually exclusive   
    1. file access and network access     
    2. device access and file access   
    3. device access and network access   


## Application identification   
   1. name based   
   2. linked dynamic lib confirm      
   3. provided functions confirm
   4. builtin string searching        