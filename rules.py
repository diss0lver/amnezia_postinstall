#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import config

config = config.Config()

system_default_rules = [
    "INPUT -i lo -j ACCEPT",
    "INPUT -p tcp -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
    "INPUT -p udp -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
]

amnezia_default_filter_rules = [
    "INPUT -p icmp -m icmp --icmp-type 8 -j DROP",
    "FORWARD -j DOCKER-USER",
    "FORWARD -j DOCKER-ISOLATION-STAGE-1",
    "FORWARD -o amn0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
    "FORWARD -o amn0 -j DOCKER",
    "FORWARD -i amn0 ! -o amn0 -j ACCEPT",
    "FORWARD -i amn0 -o amn0 -j ACCEPT",
    "FORWARD -o docker0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
    "FORWARD -o docker0 -j DOCKER",
    "FORWARD -i docker0 ! -o docker0 -j ACCEPT",
    "FORWARD -i docker0 -o docker0 -j ACCEPT",
    "DOCKER-ISOLATION-STAGE-1 -i amn0 ! -o amn0 -j DOCKER-ISOLATION-STAGE-2",
    "DOCKER-ISOLATION-STAGE-1 -i docker0 ! -o docker0 -j DOCKER-ISOLATION-STAGE-2",
    "DOCKER-ISOLATION-STAGE-1 -j RETURN",
    "DOCKER-ISOLATION-STAGE-2 -o amn0 -j DROP",
    "DOCKER-ISOLATION-STAGE-2 -o docker0 -j DROP",
    "DOCKER-ISOLATION-STAGE-2 -j RETURN",
    "DOCKER-USER -j RETURN",
]

amnezia_default_nat_rules = [
    "PREROUTING -m addrtype --dst-type LOCAL -j DOCKER -t nat",
    "OUTPUT ! -d 127.0.0.0/8 -m addrtype --dst-type LOCAL -j DOCKER -t nat",
    "POSTROUTING -s 172.29.172.0/24 ! -o amn0 -j MASQUERADE -t nat",
    "POSTROUTING -s 172.17.0.0/16 ! -o docker0 -j MASQUERADE -t nat",
    "DOCKER -i amn0 -j RETURN -t nat",
    "DOCKER -i docker0 -j RETURN -t nat",
]

def whitelist_input_rules() -> list:
    """
    :return:    list of INPUT chain full access rules for ip addresses from whitelist
    """
    rules = []
    comment = " -m comment --comment \"" + config.COMMENT_MARKER + config.WHITELIST_COMMENT + "input_"
    for ip in config.IP_WHITELIST:
        rule = "INPUT -s " + ip + comment + ip + "\" -j ACCEPT"
        rules.append(rule)
    return rules

def whitelist_docker_user_rules() -> list:
    """
    :return:    list of DOCKER-USER chain full access rules for ip addresses from whitelist
    """
    rules = []
    comment = " -m comment --comment \"" + config.COMMENT_MARKER + config.WHITELIST_COMMENT + "docker_"
    for ip in config.IP_WHITELIST:
        rule = "DOCKER-USER -d 172.29.172.0/24 ! -i amn0 -o amn0 -s " + ip + comment + ip + "\" -j ACCEPT"
        rules.append(rule)
    return rules


def exposed_ports_docker_geo_rules(port: str, proto: str, cont_name: str, geo_list: list):
    """
    Generating geo depend ACCEPT iptables rules for DOCKER-USER chain
    and DROP rules for denied from somewhere else
    :param cont_name:   container name for comment
    :param port:        container exposed port
    :param proto:       container protocol
    :param geo_list:    list of country zones for allow access
    :return:            List of iptables rules
    """
    port_string = port + "/" + proto
    rules = []
    comment = " -m comment --comment \"" + config.COMMENT_MARKER + cont_name + "\""
    if port_string not in config.NO_EXPOSE_PORTS:
        # block anywhere except chosen country sets
        rule = "DOCKER-USER -d 172.29.172.0/24 ! -i amn0 -o amn0 -p " \
               + proto + " -m " + proto + " --dport " + port + comment + " -j DROP"
        rules.append(rule)
        for country in geo_list:
            rule = "DOCKER-USER -d 172.29.172.0/24 ! -i amn0 -o amn0 -p " \
                   + proto + " -m " + proto + " --dport " + port + " -m set --match-set " + country + " src" \
                   + comment + " -j ACCEPT"
            rules.append(rule)
    return rules


def exposed_ports_nat_rules(con_ip: str, port: str, proto: str) -> list:
    """
    List of nat table rules for current container
    :param con_ip:      container ip address
    :param port:        container port
    :param proto:       container protocol
    :return:            list of iptables rules
    """
    port_string = port + "/" + proto
    if port_string in config.NO_EXPOSE_PORTS:
        rules = []
    else:
        rules = [
            "POSTROUTING -s " + con_ip + "/32 -d " + con_ip + "/32 -p " + proto + " -m " + proto + " --dport " + port + " -j MASQUERADE -t nat",
            "DOCKER ! -i amn0 -p " + proto + " -m " + proto + " --dport " + port + " -j DNAT --to-destination " + con_ip + ":" + port + " -t nat",
        ]
    return rules


def ssh_geo_iptables_rules(port: str, geo_list: list) -> list:
    """
    Generating list of iptables ssh access rules for every country zone specified in config
    :param port:
    :param geo_list:
    :return:
    """
    rules = []
    if len(geo_list) > 0:
        for country in geo_list:
            comment = " -m comment --comment \"" + config.COMMENT_MARKER + config.SSH_COMMENT + port + "\""
            rule = "INPUT -p tcp -m tcp --dport " + port + " -m set --match-set " + country + " src " + comment + " -j ACCEPT"
            rules.append(rule)
    return rules

def ip_full_access_rule(ip: str) -> str:
    """
    Generating one iptables rule with full access from specified ip address
    :param ip:      ip address for access
    :return:        iptables rule
    """
    comment = " -m comment --comment \"" + config.COMMENT_MARKER + config.AUTO_DETECTED_ADMIN_COMMENT + ip + "\""
    rule = "INPUT -s " + ip + comment + " -j ACCEPT"
    return rule


