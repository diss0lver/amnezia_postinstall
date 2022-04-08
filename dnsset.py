#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import config
from misc import syscommand, check_ip
from dockerset import container_id, replace_file_in_container, docker_bin
from dsrLogger import logger as log

config = config.Config()

def dns_current_a_records() -> list:
    """
    :return:  list of current dns a records from dns container
    """
    line_list = []
    command = docker_bin + " exec " + config.DNS_CONT_NAME + " cat " + config.DNS_CONT_A_FILE
    res = syscommand(command=command)
    for line in res:
        line_list.append(line)
    return line_list

def dns_hosts_parsed() -> list:
    """
    Reading local dns_hosts file, parse it and prepare list for inserting to dns container a-records file
    :return:    list of dns a records (local-data: "host1.example.com. A 10.1.1.30" # user defined)
    """
    line_list = []
    with open(config.DNS_HOSTS_FILE, 'r') as h:
        for line in h:
            line = line.rstrip()
            if line:
                if not line.startswith("#"):
                    try:
                        parts = line.split(",")
                        host = parts[0]
                        ip = parts[1]
                        if check_ip(ip=ip) is True:
                            line_to_add = "     local-data: \"" + host + ". A " + ip + "\" # user defined"
                            line_list.append(line_to_add)
                        else:
                            log.error(ip + " is not ip address! Check " + config.DNS_HOSTS_FILE + " file!")
                            log.warning("Skipping line " + line)
                    except IndexError:
                        log.error("Syntax error at line " + line + "! Check " + config.DNS_HOSTS_FILE + "file!")
                        log.warning("Skipping line " + line)
    return line_list


def dns_merged_a_records() -> list or bool:
    """
    Comparing dns records list from local dns_hosts file and list of current dns records from dns container
    :return:    merged list if changes found or False if not
    """
    changes = False
    current_list = dns_current_a_records()          # a records from container
    from_file = dns_hosts_parsed()                  # a records from local file
    comment = "# User records"                      # comment
    if comment not in current_list:
        current_list.append("# User records",)
    for rec in from_file:                           # if new record found in local file
        if rec not in current_list:
            changes = True
            current_list.append(rec)
    remove_list = []                                # list of removed records from local file
    for string in current_list:
        if "user defined" in string:                # sorting only self records
            if string not in from_file:
                changes = True
                remove_list.append(string)
    for string in remove_list:                      # removing records, which have been removed from local file
        if string in current_list:
            current_list.remove(string)
    if changes is True:
        return current_list
    else:
        return False


def dns_create_temp_file(m_list: list) -> None:
    """
    Creating temporary a-records.conf file, which will be copied to container
    :param m_list:      merged list of dns a records
    """
    with open(config.TMP_DIR + "/a-records.conf", 'w') as temp_a:
        for line in m_list:
            temp_a.write(line + "\n")


def dns_configure() -> None:
    """
    Replacing dns a records file in container with new file,
    if any changes found in local dns_hosts file
    """
    log.info("Checking dns container for required records ...")
    merged_list = dns_merged_a_records()
    if merged_list is not False:
        dns_container_id = container_id(cont_name='amnezia-dns')
        if dns_container_id is not False:
            log.info('Creating new dns user defined a records in amnezia-dns container')
            dns_create_temp_file(m_list=merged_list)
            replace_file_in_container(cont_id=dns_container_id,
                                      file_to_replace=config.DNS_CONT_A_FILE,
                                      new_file=config.TMP_DIR + "/a-records.conf")
        else:
            log.error('No dns container found! Install it or disable DNS_USER_RECORDS option in config file!')
    else:
        log.info('All dns records are equal')
    log.info("The dns container is processed")

if __name__ == '__main__':
    dns_configure()
