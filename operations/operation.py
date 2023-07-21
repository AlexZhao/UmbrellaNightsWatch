#!/usr/bin/python
# Main entry for all supported operations
# Operations mainly used to clean running environment and sanity check

from operations.kmod import KModOperation 
from operations.dev import DevOperation
from operations.fs import FSOperation
from operations.cred import CredOperation

class NWOperations:
    def __init__(self):
        """
        NightWatch builtin environment sanity check operations
        """
        self.ops = dict({})
        # TODO all operation instance on the fly modifable
        self.ops["kmod"] = KModOperation()
        self.ops["dev"] = DevOperation()
        self.ops["fs"] = FSOperation()
        self.ops["cred"] = CredOperation()

    def execute_operation(self, op_group, op, params=None):
        if op_group in self.ops:
            return self.ops[op_group].execute_operation(op, params)
        else:
            print("Not supported operation set ", op_group)
            return None

    def list_operations(self, op_group):
        """
        list all available operations
        """

    def list_ops(self):
        """
        list all supported operation group
        """

    def setup(self):
        self.execute_operation("kmod", "unload_no_ref_kmod")
        self.execute_operation("dev", "scan_device_map")

if __name__ == '__main__':
    Ops = NWOperations()

    kmod_list = dict({
        "i915": "1",
        "nvme": "1",
        "r8169": "1",
        "xfs": "1",
        "binfmt_misc": "1",
        "video": "1"
    })

    Ops.execute_operation("kmod", "unload_no_ref_kmod", kmod_list)

    Ops.execute_operation("dev", "scan_device_map")