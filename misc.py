#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import config
import socket
import binascii
import fileinput
import ipaddress
import sys
from dsrLogger import logger as log
from parse import parse_ip
from subprocess import Popen, PIPE

config = config.Config()

def syscommand(command: str) -> list:
    """
    Executing command by shell. Return result list or error list
    :param command:     command to execute
    """
    proc = Popen(command, shell=True, stdout=PIPE, stderr=PIPE)
    proc.wait()
    res = proc.communicate()
    if proc.returncode:
        error_list = []
        a = res[1]
        a = str(a, "utf-8")
        error_list.append(a)
        for elem in error_list:
            if elem == "":
                error_list.remove("")
        return error_list
    b = res[0]
    b = str(b, "utf-8")
    result_list = b.split("\n")
    for elem in result_list:
        if elem == "":
            result_list.remove("")
    return result_list

def find_bin(bin_file: str) -> str or bool:
    """
    Trying to find binary absolute path using whereis command.
    Package 'util-linux' must be present.
    :param bin_file:    binary to find
    :return:            absolute path or false
    """
    command = "whereis " + bin_file
    res = syscommand(command=command)[0]
    if "not found" in res:
        message = "whereis command not found! Package 'util-linux' required"
        log.critical(message)
        print(message)
        raise SystemExit
    else:
        path = False
        parts = res.split(":")
        if len(parts[1]) == 0:
            log.debug("Binary " + bin_file + " not found!")
        else:
            parts = res.split(" ")
            for part in parts:
                if "bin" in part:
                    log.debug("Binary " + bin_file + " found at " + part)
                    path = part
        return path


def current_ssh_connections() -> list:
    """
    :return:  list of current ssh connections
    """
    ip_list = []
    netstat_bin = find_bin(bin_file='netstat')
    command = netstat_bin + " -ntpe | grep sshd | cut -f 2 -d \":\""
    res = syscommand(command=command)
    if res:
        for line in res:
            ip = parse_ip(line)
            if ip not in ip_list:
                ip_list.append(ip)
                log.info("Current ssh connection detected from " + ip)
    return ip_list


def current_ssh_port() -> str or bool:
    """
    Detecting which port listen ssh daemon
    :return:
    """
    log.info("Detecting ssh port ...")
    lsof_bin = find_bin(bin_file='lsof')
    port = False
    command =  lsof_bin + " -nPi | grep sshd | grep LISTEN | grep -v IPv6 | grep -v 127.0.0.1 | head -n 1"
    res = syscommand(command=command)
    if res:
        port = res[0].split(":")[1]
        port = port.split(" ")[0]
    log.info("Ssh listening on port " + port)
    return port


def split_ports(line: str) -> tuple:
    """
    :param line:    line to split
    :return:        Split string such as 1194/udp to tuple 1194, udp
    """
    parts = line.split("/")
    port = parts[0]
    proto = parts[1]
    return port, proto


def merged_geo_list() -> list:
    """
    Merging country zones specified in config file to one list
    """
    merged_list = []
    for zone in config.AMNEZIA_GEO_RESTRICT:
        if zone not in merged_list:
            merged_list.append(zone)
    for zone in config.SSH_GEO_RESTRICT:
        if zone not in merged_list:
            merged_list.append(zone)
    return merged_list


def ip_to_integer(ip_address: str) -> tuple:
    """
    Converts an IP address expressed as a string to its
    representation as an integer value and returns a tuple
    (ip_integer, version), with version being the IP version
    (either 4 or 6).
    Both IPv4 addresses (e.g. "192.168.1.1") and IPv6 addresses
    (e.g. "2a02:a448:ddb0::") are accepted.
    :param ip_address       ip address to convert
    """
    # try parsing the IP address first as IPv4, then as IPv6
    for version in (socket.AF_INET, socket.AF_INET6):
        try:
            ip_hex = socket.inet_pton(version, ip_address)
            ip_integer = int(binascii.hexlify(ip_hex), 16)
            if version == socket.AF_INET:
                return ip_integer, 4
            else:
                return ip_integer, 6
        except Exception as err:
            log.error(err)
    raise ValueError("invalid IP address")


def subnetwork_to_ip_range(subnetwork: str) -> tuple:
    """
    Returns a tuple (ip_lower, ip_upper, version) containing the
    integer values of the lower and upper IP addresses respectively
    in a subnetwork expressed in CIDR notation (as a string), with
    version being the subnetwork IP version (either 4 or 6).
    Both IPv4 subnetworks (e.g. "192.168.1.0/24") and IPv6
    subnetworks (e.g. "2a02:a448:ddb0::/44") are accepted.
    :param subnetwork       subnetwork to getting range
    """
    try:
        fragments = subnetwork.split('/')
        network_prefix = fragments[0]
        netmask_len = int(fragments[1])
        # try parsing the subnetwork first as IPv4, then as IPv6
        for version in (socket.AF_INET, socket.AF_INET6):
            if version == socket.AF_INET:
                ip_len = 32
            else:
                ip_len = 128
            try:
                suffix_mask = (1 << (ip_len - netmask_len)) - 1
                netmask = ((1 << ip_len) - 1) - suffix_mask
                ip_hex = socket.inet_pton(version, network_prefix)
                ip_lower = int(binascii.hexlify(ip_hex), 16) & netmask
                ip_upper = ip_lower + suffix_mask
                if version == socket.AF_INET:
                    return ip_lower, ip_upper, 4
                else:
                    return ip_lower, ip_upper, 6
            except Exception as err:
                log.error(err)
    except Exception as err:
                log.error(err)
    raise ValueError("invalid subnetwork")


def ip_in_subnetwork(ip_address: str, subnetwork: str) -> bool:
    """
    Returns True if the given IP address belongs to the
    subnetwork expressed in CIDR notation, otherwise False.
    Both parameters are strings.
    Both IPv4 addresses/subnetworks (e.g. "192.168.1.1"
    and "192.168.1.0/24") and IPv6 addresses/subnetworks (e.g.
    "2a02:a448:ddb0::" and "2a02:a448:ddb0::/44") are accepted.
    :param ip_address       ip address to check
    :param subnetwork       subnetwork for check
    """
    ip_integer, version1 = ip_to_integer(ip_address=ip_address)
    ip_lower, ip_upper, version2 = subnetwork_to_ip_range(subnetwork=subnetwork)
    if version1 != version2:
        raise ValueError("incompatible IP versions")
    return ip_lower <= ip_integer <= ip_upper

def replace_string_in_file(file:str, old_val: str, new_val: str) -> None:
    """
    Change line in file
    :param file:            file to change
    :param old_val:         old string
    :param new_val:         new string
    """
    for line in fileinput.input(files=file, inplace=True):
        line = line.replace(old_val, new_val)
        sys.stdout.write(line)

def check_ip(ip: str)-> bool:
    """
    Validate ip address
    :param ip:      ip address to validate
    :return:        True or False
    """
    if type(ip) is str:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return False
        else:
            return True
    else:
        return False

def check_input(val: str, length: int) -> bool:
    """
    :param val:     value to check
    :param length:  max available value
    :return:        True if value is integer and less than specified length
    """
    try:
        int(val)
        if int(val) <= int(length):
            return True
        else:
            return False
    except ValueError:
        return False



def select(items: list or tuple, joined=True, itemname="item") -> str:
    """
    Selecting item from items
    :param items:       items for select
    :param joined:      join with "," or not
    :param itemname:    name of item which will be displayed
    :return:
    """
    print("Select " + str(itemname) + ":")
    print("")
    for i in range(len(items)):
        if joined is True:
            print(str(i + 1) + ") " + str(",".join(items[i])))
        else:
            print(str(i + 1) + ") " + str(items[i]))
    print("")
    print("0) cancel")
    choise = input()
    while check_input(choise, len(items)) is False:
        print("Value must be integer from 0 to " + str(len(items)))
        choise = input()
    else:
        if int(choise) == 0:
            raise SystemExit
        else:
            selected = items[int(choise) - 1]
            return selected

def index_of_line_contains(file_for_search: str, string_to_search: str) -> int or bool:
    """
    :param file_for_search:
    :param string_to_search:
    :return:                    number of file line, which contains specified string
    """
    with open(file_for_search, 'r') as rc:
        contents = rc.readlines()
        i = 0
        for line in contents:
            i += 1
            if string_to_search in line:
                return i
    return False


def check_string_in_file(s_file: str, string_to_check: str, ind: int) -> None:
    """
    Searching string in file. Insert it, if not found
    :param s_file:                file for searching
    :param string_to_check:     searching string
    :param ind:                 number of line of file to insert
    :return:
    """
    found = False
    with open(s_file, 'r') as rc:
        for line in rc:
            if string_to_check in line:
                found = True
    if found is False:
        with open(s_file, 'r') as rc:
            contents = rc.readlines()
            contents.insert(ind, string_to_check + "\n")
        with open(s_file, 'w') as rc:
            contents = "".join(contents)
            rc.write(contents)


def insert_to_index_of_file(file_to_insert: str, string_to_insert: str, ind: int) -> None:
    """
    Inserting string to top of file
    :param ind:                 line of file for inserting
    :param file_to_insert:      file for inserting
    :param string_to_insert:    string to insert
    :return:
    """
    with open(file_to_insert, 'r') as rc:
        contents = rc.readlines()
        contents.insert(ind, string_to_insert + "\n")
    with open(file_to_insert, 'w') as rc:
        contents = "".join(contents)
        rc.write(contents)

