#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from misc import syscommand, ip_in_subnetwork
from parse import parse_ip, parse_cidr, parse_ip_from_route

def host_default_route() -> str or bool:
    """
    :return:            default route ip address of False if not
    """
    command = "ip route|awk '/default/ { print $3 }'"
    res = syscommand(command)
    if res:
        route = parse_ip(res[0])
        return route
    else:
        return False

def host_cidr_list() -> list:
    """
    :return:            list of subnetworks from routing table
    """
    cidr_list = []
    command = "ip route"
    res = syscommand(command=command)
    if res:
        for line in res:
            cidr = parse_cidr(string=line)
            if cidr is not False:
                cidr_list.append(cidr)
    return cidr_list


def host_ipaddresses() -> list:
    """
    :return:            list of ip addresses from routing table
    """
    ip_list = []
    command = "ip route"
    res = syscommand(command=command)
    if res:
        for line in res:
            ip = parse_ip_from_route(string=line)
            if ip is not False:
                ip_list.append(ip)
    return ip_list


def host_default_cidr(def_route: str, cidr_list: list) -> str:
    """
    :param def_route:   default route ip address
    :param cidr_list:   list of subnetworks from routing table
    :return:            subnetwork which default route ip address belongs
    """
    for cidr in cidr_list:
        if ip_in_subnetwork(ip_address=def_route, subnetwork=cidr) is True:
            return cidr


def host_default_ip(ip_list: list, cidr: str) -> str:
    """
    :param ip_list:     list of ip addresses from routing table
    :param cidr:        subnetwork which default route ip address belongs
    :return:            default ip address
    """
    for ip in ip_list:
        if ip_in_subnetwork(ip_address=ip, subnetwork=cidr) is True:
            return ip


def find_ip_by_default_route() -> str:
    """
    Searching for default ip address by default route ip address
    :return:            container default ip address
    """
    default_route = host_default_route()
    h_cidr_list = host_cidr_list()
    h_addresses = host_ipaddresses()
    h_def_cidr = host_default_cidr(def_route=default_route, cidr_list=h_cidr_list)
    ip = host_default_ip(ip_list=h_addresses, cidr=h_def_cidr)
    return ip

def host_ifaces() -> list:
    """
    :return:    list of host interfaces
    """
    if_list = []
    command = "ip -4 -o a | cut -d ' ' -f 2,7 | cut -d '/' -f 1"
    res = syscommand(command=command)
    if res:
        for line in res:
            if_list.append(line)
    return if_list

def find_iface_name_by_ip(ip: str, iface_list: list) -> str or bool:
    """
    :param ip:              default host ip address
    :param iface_list:      list of host interfaces
    :return:                name of host default interface of False if not
    """
    for line in iface_list:
        if ip in line:
            parts = line.split(" ")
            def_iface = parts[0]
            return def_iface
    return False

