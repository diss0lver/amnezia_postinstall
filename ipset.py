#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import config
import os
from misc import syscommand, merged_geo_list
from dsrLogger import logger as log
from country_zones import country_zones

config = config.Config()
merged_zone_list = merged_geo_list()

def create_ipset_lists(countries: list) -> None:
    """
    Configuring ipset. Creating list and fill it
    :return:
    """
    for country in countries:
        command = "wget -P " + config.TMP_DIR + " " + config.GEO_URL + country + ".zone"
        download_complete = syscommand(command)
        if len(download_complete) != 0:
            log.info(download_complete[0])
            raise SystemExit
        else:
            command = "ipset flush " + country + " &>/dev/null"
            syscommand(command)
            log.info("Creating and filling country list: " + country + ". It can take some time...")
            command = "ipset create " + country + " hash:net &>/dev/null"
            syscommand(command)
            with open(config.TMP_DIR + "/" + country + ".zone", 'r') as zone_file:
                for line in zone_file:
                    cidr = line.strip()
                    log.debug('Adding ' + str(cidr) + ' to ' + country + " ipset list")
                    command = "ipset add " + country + " " + cidr
                    syscommand(command)
            log.info("Ipset list for country " + country + " created")
        log.info("............................................................")
        os.remove(config.TMP_DIR + "/" + country + ".zone")


def create_ipset_unit() -> None:
    """
    Creating systemd unit for save un restore ipset lists on reboot
    :return:
    """
    log.info("Creating ipset systemd unit..")
    with open(config.IPSET_UNIT_FILE, 'w') as unit:
        unit.write("[Unit]\n"
                   "Description=ipset persistent rule service\n"
                   "Before=netfilter-persistent.service\n"
                   "ConditionFileNotEmpty=/etc/iptables/ipset\n\n"
                   "[Service]\n"
                   "Type=oneshot\n"
                   "RemainAfterExit=yes\n"
                   "ExecStart=/sbin/ipset -exist  -file /etc/iptables/ipset restore\n"
                   "ExecStop=/sbin/ipset -file /etc/iptables/ipset save\n\n"
                   "[Install]\n"
                   "WantedBy=multi-user.target")
    command = "systemctl daemon-reload"
    syscommand(command)
    command = "systemctl enable " + config.IPSET_UNIT_NAME
    syscommand(command)
    command = "systemctl start " + config.IPSET_UNIT_NAME
    syscommand(command)


def save_ipset_rules() -> None:
    """
    Saving ipset lists to file
    :return:
    """
    command = "ipset -file " + config.IPSET_LISTS_FILE + " save"
    syscommand(command)


def check_ipset_unit() -> bool:
    """
    Check if exist ipset systemd unit
    :return:    True of False
    """
    command = "systemctl list-units | grep " + config.IPSET_UNIT_NAME
    res = syscommand(command)
    if res:
        return True
    else:
        return False


def current_ipset_lists() -> list:
    """
    :return:        List of existing ipset lists
    """
    ipset_lists = []
    command = "ipset list -t | grep Name"
    res = syscommand(command=command)
    for line in res:
        country = line.split(":")[1].strip()
        ipset_lists.append(country)
    return ipset_lists

def ipset_configure() -> None:
    """
    Configuring ipset lists
    :return:
    """
    log.info("Looking for required ipset lists...")
    # recreate ipset list on every run
    if config.IPSET_EVERY_RECREATE is True:
        create_ipset_lists(countries=merged_zone_list)
    else:
        half_list = []
        exist_lists = current_ipset_lists()
        for zone in merged_zone_list:
            if zone not in exist_lists:
                half_list.append(zone)
            else:
                log.info("Ipset list with zone " + zone + " already exist")
        create_ipset_lists(countries=half_list)
    save_ipset_rules()
    if check_ipset_unit() is False:
        create_ipset_unit()


def destroy_ipset_unneeded_lists() -> None:
    """
    Destroy obsolete ipset lists
    :return:
    """
    log.info("Detecting obsolete ipset lists...")
    found = False
    cur_ipset_lists = current_ipset_lists()
    for ls in cur_ipset_lists:
        if ls not in merged_zone_list:
            # prevent removing non geo lists
            if ls in country_zones:
                found = True
                command = 'ipset destroy ' + ls
                res = syscommand(command=command)
                if len(res) > 0:
                    log.error(res)
                else:
                    log.warn('Ipset list ' + ls + " removed")
    if found is True:
        save_ipset_rules()
    log.info("The ipset lists are processed")

if __name__ == '__main__':
    ipset_configure()
    destroy_ipset_unneeded_lists()

