#!/usr/bin/python
# Apache License V2
# Copyright Alex Zhao
# NightsWatch CLI interface
# 
import click
from click_shell import shell
import subprocess;
import json;


class BufferedData :
    def __init__(self):
        self.monitored_app = dict({})
    
    def update_monitored_app(self, app_list):
        for app in app_list:
            if app not in self.monitored_app:
                self.monitored_app[app] = dict({})

    def get_under_monitor_app_list(self):
        app_list = []
        for app, _ in self.monitored_app.items():
            app_list.append(app)
        
        return app_list

    def update_dump_details(self, app, details):
        self.monitored_app[app] = details


    def get_monitored_app_details(self):
        return self.monitored_app

# microscope endpoint
TELE_URI = "http://127.0.0.1:8277"

cached_res = BufferedData()

@shell(prompt='nw-cli -> ', intro='NW Commandline interface ...')
def nw_cli():
    pass

@nw_cli.command()
def list_monitored_app():
    curl_str = "{}/list_mon".format(TELE_URI)
    list_monitor = subprocess.Popen(['curl', '-s', curl_str], stdout=subprocess.PIPE)
    output = list_monitor.stdout.read().decode("utf-8")
    try:
        under_mon_app = json.loads(output)
        if under_mon_app['result'] == 'success':
            print("Below Application has monitored activities   ")
            for app in under_mon_app['details']:
                print("  -> ", app)
            cached_res.update_monitored_app(under_mon_app['details'])
    except:
        print("Error when list monitored application")

@nw_cli.command()
@click.option('--app', required = True)
def show_monitored_app(app):
    curl_str = "{}/dump_mon?proc={}".format(TELE_URI, app)
    show_monitor = subprocess.Popen(['curl', '-s', '-X', 'POST', curl_str], stdout=subprocess.PIPE)
    output = show_monitor.stdout.read().decode("utf-8")
    try:
        show_mon_app = json.loads(output)
        if show_mon_app['result'] == 'success':
            file_access = show_mon_app['details']['file_access']
            dev_access = show_mon_app['details']['dev_access']
            net_access = show_mon_app['details']['net_access']
            exec_access = show_mon_app['details']['execv_access']
            syscalls = show_mon_app['details']['seldom_syscall']

            print(app, "Has below IO and system behavior...")
            print("   File Access -->")
            for file in file_access:
                for filename, cnt in file.items(): 
                    print("        ", filename)
            
            print("   Device Access -->")
            for dev, acc in dev_access.items():
                print("        ", dev)
            
            print("   Network Access -->")
            tcp = show_mon_app['details']['net_access']['TCP']
            udp = show_mon_app['details']['net_access']['UDP']
            unix = show_mon_app['details']['net_access']['UNIX']
            print("   TCP ---->")
            for ip, cnt in tcp.items():
                print("        ", ip)
            print("   UDP ---->")
            for ip, cnt in udp.items():
                print("        ", ip)
            print("   UNIX ---->")
            for ip, cnt in unix.items():
                print("        ", ip)
            
            print("   Execve -->")
            for execv, detail in exec_access.items():
                print("        ", execv)
                for cmd, cnt in detail.items():
                    print("              ", cmd)

            print("   Syscall -->")
            for syscall, cnt in syscalls.items():
                print("        ", syscall)

    except:
        print("Error when dump monitored application")
        print(output)


@nw_cli.command()
def update_monitor_details():
    app_list = cached_res.get_under_monitor_app_list()
    for app in app_list:
        curl_str = "{}/dump_mon?proc={}".format(TELE_URI, app)
        dump_res = subprocess.Popen(['curl', '-s', '-X', 'POST', curl_str], stdout=subprocess.PIPE)
        output = dump_res.stdout.read().decode('utf-8')
        try:
            res = json.loads(output)
            cached_res.update_dump_details(app, res)
        except:
            print("Error when get details of {}".format(app))

@nw_cli.command()    
@click.option('--exe', required = True)
def cross_search_execv(exe):
    details = cached_res.get_monitored_app_details()
    for app, detail in details.items():
        try:
            if detail['result'] == 'success':
                exec_access = detail['details']['execv_access']
                for execv, info in exec_access.items():
                    executed_cmd = execv.split('/')[-1]
                    if exe == executed_cmd:
                        print(app, " executed  ", execv)
        except:
            print("parsing data failed, refresh cache to run update_monitor_details")


@nw_cli.command()
@click.option('--file', required = True)
def cross_search_file(file):
    details = cached_res.get_monitored_app_details()
    for app, detail in details.items():
        try:
            if detail['result'] == 'success':
                file_access = detail['details']['file_access']
                for f in file_access:
                    for file_name, cnt in f.items():
                        open_file_name = file_name.split('/')[-1]
                        if open_file_name == file:
                            print(app, "  opened file  ", file_name)
        except:
            print("parsing data failed, refresh cache to run update_monitor_details")

@nw_cli.command()
@click.option('--lsm', required = True)
@click.option('--config')
def reload_lsm(lsm, config=None):
    curl_str = "{}/lsm/{}".format(TELE_URI, lsm)
    if config != None:
        reload = subprocess.Popen(['curl', '-s', '-X', 'POST', '-d', 'cmd=reload_ebpf_lsm', '-d', 'config={}'.format(config), curl_str], stdout=subprocess.PIPE)
    else:
        reload = subprocess.Popen(['curl', '-s', '-X', 'POST', '-d', 'cmd=reload_ebpf_lsm', curl_str], stdout=subprocess.PIPE)
    output = reload.stdout.read().decode("utf-8")
    try:
        reload_res = json.loads(output)
        if reload_res["reload_lsm"] == "success":
            print("   Reload [{}] Success".format(lsm))
        else:
            print("   Reload [{}] Failed".format(lsm))
    except:
        print("Error when reload ebpf LSM")
        print(output)

@nw_cli.command()
def list_lsm():
    curl_str = "{}/lsm".format(TELE_URI)
    list = subprocess.Popen(['curl', '-s', curl_str], stdout=subprocess.PIPE)
    output = list.stdout.read().decode("utf-8")
    try:
        list_res = json.loads(output)
        if list_res['result'] == "success":
            print("  Equipped LSM -->")
            for lsm in list_res['details']:
                print("        ", lsm)
        else:
            print("  Failed to get loaded LSMs")
    except:
        print("Error when list eBPF LSM")
        print(output)

@nw_cli.command()
@click.option('--lsm', required = True)
@click.option('--config')
def add_lsm(lsm, config=None):
    curl_str = "{}/lsm".format(TELE_URI)
    if config != None:
        add = subprocess.Popen(['curl', '-s', '-X', 'POST', '-d', 'cmd=add_ebpf_lsm', '-d', 'lsm={}'.format(lsm), '-d', 'config={}'.format(config), curl_str], stdout=subprocess.PIPE)
    else:
        add = subprocess.Popen(['curl', '-s', '-X', 'POST', '-d', 'cmd=add_ebpf_lsm', '-d', 'lsm={}'.format(lsm), curl_str], stdout=subprocess.PIPE)

    output = add.stdout.read().decode("utf-8")
    try:
        add_res = json.loads(output)
        if add_res["add_lsm"] == "success":
            print("   Add [{}] Success".format(lsm))
        else:
            print("   Add [{}] Failed".format(lsm))
    except:
        print("Error when add ebpf LSM")
        print(output)

@nw_cli.command()
@click.option('--lsm', required = True)
def config_lsm(lsm):
    curl_str = "{}/lsm/{}".format(TELE_URI, lsm)


@nw_cli.command()
def list_prb():
    curl_str = "{}/prb".format(TELE_URI)
    list = subprocess.Popen(['curl', '-s', curl_str], stdout=subprocess.PIPE)
    output = list.stdout.read().decode("utf-8")
    try:
        list_res = json.loads(output)
        if list_res['result'] == "success":
            print("  Equipped PRB -->")
            for lsm in list_res['details']:
                print("        ", lsm)
        else:
            print("  Failed to get loaded PRBs")
    except:
        print("Error when list eBPF PRB")
        print(output)

@nw_cli.command()
@click.option("--prb", required = True)
def reload_prb(prb):
    curl_str = "{}/prb/{}".format(TELE_URI, prb)
    reload = subprocess.Popen(['curl', '-s', '-X', 'POST', '-d', 'cmd=reload_ebpf_prb', curl_str], stdout=subprocess.PIPE)
    output = reload.stdout.read().decode("utf-8")
    try:
        reload_res = json.loads(output)
        if reload_res["reload_prb"] == "success":
            print("   Reload [{}] Success".format(prb))
        else:
            print("   Reload [{}] Failed".format(prb))
    except:
        print("Error when reload ebpf PRB")
        print(output)

@nw_cli.command()
@click.option("--prb", required = True)
@click.option("--config")
def add_prb(prb, config=None):
    curl_str = "{}/prb".format(TELE_URI)
    if config != None:
        add = subprocess.Popen(['curl', '-s', '-X', 'POST', '-d', 'cmd=add_ebpf_prb', '-d', 'prb={}'.format(prb), '-d', 'config={}'.format(config), curl_str], stdout=subprocess.PIPE)
    else:
        add = subprocess.Popen(['curl', '-s', '-X', 'POST', '-d', 'cmd=add_ebpf_prb', '-d', 'prb={}'.format(prb), curl_str], stdout=subprocess.PIPE)

    output = add.stdout.read().decode("utf-8")
    try:
        add_res = json.loads(output)
        if add_res["add_prb"] == "success":
            print("   Add [{}] Success".format(prb))
        else:
            print("   Add [{}] Failed".format(prb))
    except:
        print("Error when add ebpf PRB")
        print(output)


@nw_cli.command()
@click.option("--app", required = True)
def quarantine_app(app):
    """
    Pattern based lockdown application in different level
    compare to lockdown kernel, it only lockdown defined application
    """
    

if __name__ == '__main__':
    nw_cli()
