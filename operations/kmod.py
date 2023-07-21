# loaded kernel module unload/clean
import subprocess

class KModOperation:
    def __init__(self):
        """
        KMod supported operations
        """

    def execute_operation(self, op, params=None):
        match op:
            case "unload_no_ref_kmod":
                return self.unload_all_no_ref_kmod(params)
            case _:
                return False

    def unload_all_no_ref_kmod(self, kmod_list):
        try:
            rmmod_kmod_cnt = 1
            while rmmod_kmod_cnt > 0:
                rmmod_kmod_cnt = 0
                all_loaded_kmod = subprocess.Popen(['lsmod'], stdout=subprocess.PIPE)
                output = all_loaded_kmod.stdout.readline().decode('utf-8')
                while output:
                    kmod_info = output.split()
                    try:
                        if int(kmod_info[2]) == 0:
                            if not kmod_info[0] in kmod_list:
                                rmmod_info = subprocess.Popen(['rmmod', kmod_info[0]], stdout=subprocess.PIPE)
                                rmmod_kmod_cnt = rmmod_kmod_cnt + 1
                    except:
                        if kmod_info[2] != "Used":
                            print("not able to unload kmod ", kmod_info[0])

                    output = all_loaded_kmod.stdout.readline().decode('utf-8')
        except:
            print("unload kmod exception")
        
        return True
    
    def elf_binary_kmod_analysis(self, kmod_name):
        """
        Check kmod elf binary dynamic linked kernel symbols
        """
        