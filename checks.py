#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import config
from misc import check_ip, split_ports
from dsrLogger import logger as log
from country_zones import country_zones

config = config.Config()

def check_zones() -> bool:
    """
    Checking specified in config file country zones for correctness
    :return:
    """
    for zone in config.AMNEZIA_GEO_RESTRICT:
        if zone not in country_zones:
            log.critical("Wrong country zone '" + str(zone) + "'! Check AMNEZIA_GEO_RESTRICT parameter in config file!")
            raise SystemExit
    for zone in config.SSH_GEO_RESTRICT:
        if zone not in country_zones:
            log.critical("Wrong country zone '" + str(zone) + "'! Check SSH_GEO_RESTRICT parameter in config file!")
            raise SystemExit
    return True


def check_whitelist() -> bool:
    """
    Checking whitelist for correct ip addresses
    :return:
    """
    for ip in config.IP_WHITELIST:
        if check_ip(ip=ip) is False:
            log.critical("Syntax error at line " + ip + "! Check whitelist in config file!")
            raise SystemExit
    return True


def check_policy_values() -> bool:
    """
    Checking iptables default policy values for correct actions
    :return:
    """
    actions = ['ACCEPT', 'DROP', 'REJECT']
    for param in dir(config):
        if not param.startswith("_"):
            if 'INPUT_POLICY' in param or 'FORWARD_POLICY' in param:
                val = getattr(config, param)
                if val not in actions:
                    log.critical("Syntax error at " + param + "! Value '" + val + "' is not acceptable!")
                    raise SystemExit
    return True

def check_no_expose_ports() -> bool:
    """
    Checking for right definition port and protocol values (1194/udp)
    :return:
    """
    protocols = ['tcp', 'udp']
    for line in config.NO_EXPOSE_PORTS:
        port, proto = split_ports(line=line)
        try:
            int(port)
        except ValueError:
            log.critical("Wrong value '" + line + "' given in NO_EXPOSE_PORTS config parameter")
            raise SystemExit
        if proto not in protocols:
            log.critical("Wrong value '" + line + "' given in NO_EXPOSE_PORTS config parameter")
            raise SystemExit
    return True

def check_config() -> None:
    """
    Running all checks
    :return:
    """
    check_zones()
    check_whitelist()
    check_policy_values()
    check_no_expose_ports()

if __name__ == '__main__':
    check_config()

