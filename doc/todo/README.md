## TODO List   
  1. trace the folder   
  2. track to device according to path  
  3. ebpf_event.h each section has type, len, contents format  
  4. configure nw to based on RT SCHED to avoid be jammed by scheduler config   
  5. kmod and behavior chained operation, detect device on bus, load kmod, after use unload kmod
  6. Device type based access control Audio, Video, ...
  

## Kernel related modification needed to better security control    
  1. simplify_symbols/apply_relocations  
      a. add security hooks to control dynamic linked symbol   
  2. 

## Architecture modification   (achieve all stuffs can be dynamic loaded)    
  1. prb - > Probe modify to work like lsm    
  2. runtime reload analysis   


## Probe event log   
  1. TLV   
     type:length:value    
       0:?:string    
       1:?:sockaddr    

um_prb     
        ^          ^            ^       ^        ^                ^
        |          |            |       |        |                |
bpf                            int64   str     int               TLV
        ^          ^            ^       ^        ^                ^
        |          |            |       |        |                |
    [prb_name]:[probe_func]:[timestamp]:[app_name]:[pid]: -> [converted_str] [converted_str] ... 


  2. ApplicationProfile associate with
      [prb_name]:[probe_func] ->  


  3. 


## Binfmt  

   bprm->buf  elf header  
   
