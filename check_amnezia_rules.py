#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import config
from dockerset import detected_amnezia_containers
from misc import split_ports
from dockerset import container_exposed_ports, find_cont_ip_by_default_route
from iptables import remove_wrong_postrouting_rules
from dsrLogger import logger as log

config = config.Config()

def check_amnezia_rules():
    """
    Checking for obsolete POSTROUTING rules in nat table after reboot
    :return:
    """
    containers = detected_amnezia_containers()
    if containers is False:
        raise SystemExit
    for container in containers:
        ports = container_exposed_ports(container=container)
        if ports:
            con_ip = find_cont_ip_by_default_route(container=container)
            for line in ports:
                if line not in config.NO_EXPOSE_PORTS:
                    port, proto = split_ports(line=line)
                    remove_wrong_postrouting_rules(ip=con_ip, proto=proto, port=port)
                else:
                    port, proto = split_ports(line=line)
                    log.warning(proto.capitalize() + " port " + port + " excluded from exposition by config")


if __name__ == '__main__':
    check_amnezia_rules()
