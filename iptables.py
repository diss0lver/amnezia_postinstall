#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import config
from dsrLogger import logger as log
from misc import \
    find_bin, \
    current_ssh_connections, \
    split_ports, \
    syscommand, \
    merged_geo_list, \
    current_ssh_port
from dockerset import \
    container_exposed_ports, \
    find_cont_ip_by_default_route, \
    detected_amnezia_containers
from rules import \
    system_default_rules, \
    amnezia_default_filter_rules, \
    amnezia_default_nat_rules, \
    exposed_ports_nat_rules, \
    exposed_ports_docker_geo_rules, \
    ip_full_access_rule, \
    ssh_geo_iptables_rules, \
    whitelist_docker_user_rules, \
    whitelist_input_rules
from parse import parse_country_set, parse_ip, parse_rule
from country_zones import country_zones

config = config.Config()
iptables_bin = find_bin(bin_file='iptables')
ip6tables_bin = find_bin(bin_file='ip6tables')
iptables_save_bin = find_bin(bin_file='iptables-save')
ip6tables_save_bin = find_bin(bin_file='ip6tables-save')
full_geo_list = merged_geo_list()


def iptables_chain_policy(ip_v: str, chain: str) -> str:
    """
    :param ip_v:    ip protocol version
    :param chain:   Iptables chain
    :return:        Current policy for specified chain
    """
    if ip_v == '4':
        command = iptables_bin + " -L " + chain + " | head -n 1"
    else:
        command = ip6tables_bin + " -L " + chain + " | head -n 1"
    res = syscommand(command=command)
    parts = res[0].split("policy")
    policy = parts[1].replace(")", "").strip()
    return policy

def set_iptables_chain_policy(ip_v: str, chain: str, action="DROP") -> None:
    """
    Setting iptables default policy for specified chain
    :param ip_v:        ip protocol version
    :param chain:       Iptables chain
    :param action:      Chain action
    """
    if ip_v == '4':
        command = iptables_bin + " -P " + chain + " " + action
    else:
        command = ip6tables_bin + " -P " + chain + " " + action
    log.info("Setting iptables " + chain + " ipv" + ip_v + " default policy to " + action)
    syscommand(command=command)


def save_iptables_rules() -> None:
    """
    Saving iptables rules for each protocol if it specified in config
    """
    if config.SAVE_V4_RULES_ON_REBOOT is True:
        command = iptables_save_bin + " > " + config.IPTABLES_RULES_v4
        syscommand(command=command)
        log.info('Iptables v4 rules saved to ' + config.IPTABLES_RULES_v4)
    if config.SAVE_V6_RULES_ON_REBOOT is True:
        command = ip6tables_save_bin + " > " + config.IPTABLES_RULES_v6
        syscommand(command=command)
        log.info('Iptables v6 rules saved to ' + config.IPTABLES_RULES_v6)


def check_iptables_rule(rule: str, top=False, write_log=True) -> None:
    """
    Checking iptables rule. Insert it if absent
    :param write_log:       no logging id False
    :param top:             insert on top of chain
    :param rule:            rule for check
    :return:
    """
    check_opt = "-C"
    add_opt = "-A"
    top_opt = "-I"
    command = iptables_bin + " " + check_opt + " " + rule
    res = syscommand(command=command)
    if res:
        if 'iptables' in res[0]:
            if top is True:
                command = iptables_bin + " " + top_opt + " " + rule
            else:
                command = iptables_bin + " " + add_opt + " " + rule
            if write_log is True:
                log.warning("Rule '" + rule + "' not found. Inserting!")
            syscommand(command=command)
        else:
            log.debug("Looks good. Rule '" + rule + "' exist")
    else:
        log.debug("Looks good. Rule '" + rule + "' exist" )


def remove_iptables_rule(rule_for_remove: str, write_log=True) -> None:
    """
    Removing iptables rule
    :param write_log:           no logging if False
    :param rule_for_remove:     rule to remove
    """
    check_opt = "-C"
    del_opt = "-D"
    command = iptables_bin + " " + check_opt + " " + rule_for_remove
    res = syscommand(command=command)
    if res:
        if 'iptables' in res[0]:
            log.debug("Rule '" + rule_for_remove + "' not found. Looks good!")
        else:
            command = iptables_bin + " " + del_opt + " " + rule_for_remove
            if write_log is True:
                log.info("Removing rule " + rule_for_remove)
            syscommand(command=command)
    else:
        command = iptables_bin + " " + del_opt + " " + rule_for_remove
        if write_log is True:
            log.info("Removing rule " + rule_for_remove)
        syscommand(command=command)



def remove_wrong_postrouting_rules(ip: str, proto: str, port: str) -> None:
    """
    Ip address of container may change after reboot. Checking for that rules and removing it
    :param ip:          container ip
    :param proto:       protocol of container exposed port
    :param port:        container exposed port
    :return:
    """
    command = iptables_save_bin
    rules = syscommand(command=command)
    for rule in rules:
        if "-A POSTROUTING -s 172.29.172." in rule:
            if " -p " + proto + " -m " + proto + " --dport " + port in rule:
                if ip not in rule:
                    log.warning("Rule " + rule + " is obsolete and will be removed!")
                    rule = rule.replace("-A ", "")
                    rule = rule + " -t nat"
                    remove_iptables_rule(rule_for_remove=rule)


def clean_obsolete_rules(ssh_port: str) -> None:
    """
    Checking for obsolete iptables rules and remove it
    :param ssh_port:    current port which listen ssh daemon
    """
    command = iptables_save_bin + " | grep " + config.COMMENT_MARKER
    res = syscommand(command=command)
    if res:
        for rule in res:
            rule = rule.replace("-A ", "")
            parsed_rule = parse_rule(string=rule)
            chain, _, _, comment = parsed_rule
            #
            if config.AUTO_DETECTED_ADMIN_COMMENT in comment:
                if config.CREATE_ACCESS_FOR_CURRENT_SSH_CONN is False:
                    remove_iptables_rule(rule_for_remove=rule)
            # если был изменен whitelist
            if config.WHITELIST_COMMENT in comment:
                ip = parse_ip(string=comment).rstrip()
                if ip not in config.IP_WHITELIST:
                    remove_iptables_rule(rule_for_remove=rule)
            # если был изменен ssh port
            if config.SSH_COMMENT in comment:
                country_set = parse_country_set(string=parsed_rule[1])
                if country_set not in config.SSH_GEO_RESTRICT:
                    if country_set in country_zones:  # prevent remove non geo lists
                            remove_iptables_rule(rule_for_remove=rule)
                port = comment.replace(config.COMMENT_MARKER + config.SSH_COMMENT, "")
                if port != ssh_port:
                    remove_iptables_rule(rule_for_remove=rule)
            # DOCKER-USER
            if config.AMNEZIA_CONT_MARKER in comment:
                country_set = parse_country_set(string=parsed_rule[1])
                if country_set not in config.AMNEZIA_GEO_RESTRICT:
                    if country_set in country_zones:  # prevent remove non geo lists
                        remove_iptables_rule(rule_for_remove=rule)
                if len(config.AMNEZIA_GEO_RESTRICT) == 0:
                    remove_iptables_rule(rule_for_remove=rule)
                # если контейнер удален или остановлен
                cont_name = comment.replace(config.COMMENT_MARKER, "")
                if cont_name not in detected_amnezia_containers():
                    remove_iptables_rule(rule_for_remove=rule)


def checking_rules(containers: list, ssh_port: str):
    """
    Checking for necessary rules
    :param ssh_port:        port which listen ssh
    :param containers:      list of amnezia docker containers
    :return:
    """
    # ssh
    current_conn = current_ssh_connections()
    log.info("Checking for full access iptables rules for current ssh connections")
    if config.CREATE_ACCESS_FOR_CURRENT_SSH_CONN is True:
        for ip in current_conn:
            full_access_rule  = ip_full_access_rule(ip=ip)
            check_iptables_rule(rule=full_access_rule, top=True)
    # ssh geo
    if len(config.SSH_GEO_RESTRICT) > 0:
        log.info("Checking for ssh rules")
        ssh_geo_rules = ssh_geo_iptables_rules(port=ssh_port, geo_list=config.SSH_GEO_RESTRICT)
        for rule in ssh_geo_rules:
            check_iptables_rule(rule=rule)
    # default rules
    log.info("Checking for necessary system iptables rules")
    for rule in system_default_rules:
        check_iptables_rule(rule=rule)
    # table filter
    log.info("Checking for necessary amnezia filter iptables rules")
    for rule in amnezia_default_filter_rules:
        check_iptables_rule(rule=rule)
    # table nat
    log.info("Checking for necessary amnezia nat iptables rules")
    for rule in amnezia_default_nat_rules:
        check_iptables_rule(rule=rule)
    # container depended rules
    for container in containers:
        ports = container_exposed_ports(container=container)
        if ports:
            con_ip = find_cont_ip_by_default_route(container=container)
            for line in ports:
                if line not in config.NO_EXPOSE_PORTS:
                    port, proto = split_ports(line=line)
                    log.info("Container " + container + " has exposed port " + port + "/" + proto)
                    log.info("Checking necessary iptables rule for port " + port + "/" + proto)
                    if len(config.AMNEZIA_GEO_RESTRICT) > 0:
                        # checking DOCKER-USER
                        for rule in exposed_ports_docker_geo_rules(port=port,
                                                                   proto=proto,
                                                                   cont_name=container,
                                                                   geo_list=config.AMNEZIA_GEO_RESTRICT):
                            check_iptables_rule(rule=rule, top=True)
                        # checking nat
                        for rule in exposed_ports_nat_rules(con_ip=con_ip, port=port, proto=proto):
                            check_iptables_rule(rule=rule)
                    remove_wrong_postrouting_rules(ip=con_ip, proto=proto, port=port)
                else:
                    port, proto = split_ports(line=line)
                    log.info(proto.capitalize() + " port " + port + " excluded from exposition by config")
    # whitelist rules
    log.info("Recreating whitelist iptables rules for chain INPUT")
    for rule in whitelist_input_rules():
        # recreating whitelist INPUT rules, place it on top
        remove_iptables_rule(rule_for_remove=rule, write_log=False)
        check_iptables_rule(rule=rule, top=True, write_log=True)
    log.info("Recreating whitelist iptables rules for chain DOCKER-USER")
    for rule in whitelist_docker_user_rules():
        # recreating whitelist DOCKER-USER rules, place it on top
        remove_iptables_rule(rule_for_remove=rule, write_log=False)
        check_iptables_rule(rule=rule, top=True, write_log=False)
    clean_obsolete_rules(ssh_port=ssh_port)


def configure_default_policy():
    """
    Checking existing default policy for both ip protocol version, chains INPUT and FORWARD.
    Setting value specified in config if does not match
    """
    # 4
    input_policy_4 = iptables_chain_policy(ip_v='4', chain="INPUT")
    if input_policy_4 != config.V4_INPUT_POLICY:
        set_iptables_chain_policy(ip_v='4', chain="INPUT", action=config.V4_INPUT_POLICY)
    forward_policy_4 = iptables_chain_policy(ip_v='4', chain="FORWARD")
    if forward_policy_4 != config.V4_FORWARD_POLICY:
        set_iptables_chain_policy(ip_v='4', chain="FORWARD", action=config.V4_FORWARD_POLICY)
    # 6
    input_policy_6 = iptables_chain_policy(ip_v='6', chain="INPUT")
    if input_policy_6 != config.V6_INPUT_POLICY:
        set_iptables_chain_policy(ip_v='6', chain="INPUT", action=config.V6_INPUT_POLICY)
    forward_policy_6 = iptables_chain_policy(ip_v='6', chain="FORWARD")
    if forward_policy_6 != config.V6_FORWARD_POLICY:
        set_iptables_chain_policy(ip_v='6', chain="FORWARD", action=config.V6_FORWARD_POLICY)



def configure_iptables(containers: list, ssh_port: str):
    """
    Configuring iptables rules
    :param ssh_port:        port which listen ssh
    :param containers:      list of amnezia docker containers
    """
    log.info("Configuring iptables ...")
    checking_rules(containers=containers, ssh_port=ssh_port)
    configure_default_policy()
    save_iptables_rules()
    log.info("The iptables rules are ok!")

if __name__ == '__main__':
    cont_list = detected_amnezia_containers()
    ssh_p = current_ssh_port()
    configure_iptables(containers=cont_list, ssh_port=ssh_p)

