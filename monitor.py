#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import config
import subprocess
from packages import package_present, install_package
from misc import select, split_ports, find_bin, replace_string_in_file
from dockerset import detected_amnezia_containers, container_exposed_ports
from hostset import find_ip_by_default_route, host_ifaces, find_iface_name_by_ip

config = config.Config()
trafshow_bin = find_bin(bin_file='trafshow')

def show_monitor(iface:str, port_lines: list, default_ip: str) -> None:
    """
    Displaying trafshow with specified parameters
    :param iface:           interface for monitor
    :param port_lines:      list of ports for monitor ([6789/tcp, 1194/udp])
    :param default_ip:      default host ip address for filter destination
    :return:
    """
    print("Detected default ip address is '" + default_ip + "'")
    print("Detected interface is '" + iface + "'")
    port_string = ""
    for port_line in port_lines:
        port, proto = split_ports(line=port_line)
        port_string = port_string + " " + proto + " dst port " + port + " or"
    port_string = port_string[:-3].strip()  # removing last 'or'
    command = trafshow_bin, \
              "-n", \
              "-P " + str(config.TRAFSHOW_PURGE_INTERVAL), \
              "-c" + config.MAIN_DIR + "/trafshow" , \
              "-i" + iface, port_string , \
              "and dst " + default_ip
    log_port_string = ""
    for port_line in port_lines:
        log_port_string = log_port_string + port_line + " "
    log_port_string = log_port_string[:-1]  # removing last space
    print("Detected ports is " + log_port_string + ".")
    print("Press 'q' many times to exit from monitor screen.")
    print("And now press 'Enter'")
    a = input()
    if not a or a:
        subprocess.run(command)

def fix_etc_trafshow() -> None:
    """
    Removing wrong line from /etc/trafshow
    :return:
    """
    with open('/etc/trafshow', 'r') as e:
        for line in e:
            if line:
                if 'timed' in line:
                    line_to_remove = line
                    replace_string_in_file(file='/etc/trafshow',
                                           old_val=line_to_remove,
                                           new_val="")


def monitor() -> None:
    """
    Displaying trafshow monitor for selected container
    :return:
    """
    # fix_etc_trafshow()
    def_ip = find_ip_by_default_route()
    if_list = host_ifaces()
    iface = find_iface_name_by_ip(ip=def_ip, iface_list=if_list)
    cont_list = detected_amnezia_containers()
    selected_container = select(items=cont_list, joined=False, itemname='container')
    ports = container_exposed_ports(container=selected_container)
    for port in config.NO_EXPOSE_PORTS:
        if port in ports:
            ports.remove(port)
    if len(ports) > 0:
        print("Connections to '" + selected_container + "' container will be displayed.")
        show_monitor(iface=iface, port_lines=ports, default_ip=def_ip)
    else:
        print("Container " + selected_container + " has no ports exposed to internet! Nothing to monitor!")


if __name__ == '__main__':
    if package_present(package_name='util-linux') is False:
        install_package(package='util-linux')
    if package_present(package_name='netdiag') is False:
        install_package(package='netdiag')
    trafshow_bin = find_bin(bin_file='trafshow')
    monitor()
