# Device info query and checking
import subprocess
import re

class DevOperation:
    def __init__(self):
        """
        Device relevant Operations
        """
        self.pci_bus_dev = dict({})
        self.dev_path = dict({})
        self.devs = dict({})

    def execute_operation(self, op, params=None):
        match op:
            case "scan_device_map":
                return self.scan_device_map()
            case _:
                return False

    def scan_device_map(self):
        pci_devices = subprocess.Popen(['lspci'], stdout=subprocess.PIPE)
        pci_device_re = re.compile("([\d\:\.abcdef]+) ([\w\W]+)", re.IGNORECASE)
        output = pci_devices.stdout.readline().decode('utf-8').strip()
        while output:
            pci_dev_match = pci_device_re.match(output)
            if pci_dev_match:
                self.pci_bus_dev[pci_dev_match.group(1)] = pci_dev_match.group(2)
            output = pci_devices.stdout.readline().decode('utf-8').strip()
        

        dev_link_re = re.compile("([\w\.]+) ([\d]+) root root 0  ([\d\:]+) -> ([\w\W]+)", re.IGNORECASE)

        char_dev = subprocess.Popen(['ls', '-l', '--time-style=+', '/sys/dev/char'], stdout=subprocess.PIPE)
        output = char_dev.stdout.readline().decode('utf-8').strip()
        while output:
            char_dev_match = dev_link_re.match(output)
            if char_dev_match:
                self.dev_path[char_dev_match.group(4)] = char_dev_match.group(3)
            output = char_dev.stdout.readline().decode('utf-8').strip()
    
        block_dev = subprocess.Popen(['ls', '-l', '--time-style=+', '/sys/dev/block'], stdout=subprocess.PIPE)
        output = block_dev.stdout.readline().decode('utf-8').strip()
        while output:
            block_dev_match = dev_link_re.match(output)
            if block_dev_match:
                self.dev_path[block_dev_match.group(4)] = block_dev_match.group(3)
            output = block_dev.stdout.readline().decode('utf-8').strip()

        for dev_path, dev_node in self.dev_path.items():
            for pci_addr, dev_name in self.pci_bus_dev.items():
                if "pci00" in dev_path and pci_addr in dev_path:
                    dev_path_split = dev_path.split('/')
                    dev = dev_path_split[len(dev_path_split) - 1]
                    self.devs[dev] = dict({"path": dev_path, "name": dev_name})

        if len(self.devs) > 0:
            return self.devs
        else:
            return None
