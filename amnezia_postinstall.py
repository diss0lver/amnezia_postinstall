#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import config
from misc import current_ssh_port
from crond import configure_crond
from ipset import ipset_configure, destroy_ipset_unneeded_lists
from rclocal import configure_rclocal
from packages import check_sys_packages_exist, set_autosave_debconf, check_misc_packages_exist
from iptables import configure_iptables
from dnsset import dns_configure
from checks import check_config
from dsrLogger import logger as log
from gitset import get_conf_form_git
from dockerset import \
    docker_bin, \
    detected_amnezia_containers, \
    set_containers_logging_off, \
    configure_container_packages

config = config.Config()
check_config()

if docker_bin is False:
    log.critical("There is no docker binary found! Try to install any container first!")
    raise SystemExit
else:
    set_autosave_debconf()  # setting autosave to iptables rules
    check_sys_packages_exist()
    ssh_port=current_ssh_port()
    containers = detected_amnezia_containers()
    if containers is False:
        log.critical("There is no amnezia container found! Try to install any container first!")
        raise SystemExit
    else:
        if len(config.AMNEZIA_GEO_RESTRICT) > 0 or len(config.SSH_GEO_RESTRICT) > 0:
            ipset_configure()
            configure_crond()
        configure_container_packages()
        configure_iptables(containers=containers, ssh_port=ssh_port)
        configure_rclocal()
    destroy_ipset_unneeded_lists()
if config.DISABLE_DOCKER_JSON_LOG is True:
    set_containers_logging_off()
if config.DNS_USER_RECORDS is True:
    dns_configure()
if len(config.MISC_PACKAGES) > 0:
    check_misc_packages_exist()
get_conf_form_git()


