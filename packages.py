#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import config
from misc import syscommand
from dsrLogger import logger as log

config = config.Config()

sys_packages = [
    'debconf-utils',
    'coreutils',
    'sudo',
    'lsof',
    'wget',
    'iptables-persistent',
    'util-linux',
    'net-tools',
    'iptables',
    'netdiag',
    'git',
]
geo_packages = [
    'ipset',
]


def insert_to_debconf(value: str) -> None:
    """
    Insert value to debconf database
    :param value:       value to insert
    :return:
    """
    command = "echo " + value + " | debconf-set-selections"
    syscommand(command)


def debconf_autosave_value(ver='v4') -> str or None:
    """
    Getting current iptables-persistent autosave value from debconf database for specified version ip
    :param ver:     ip version
    :return:
    """
    command = "debconf-get-selections | grep iptables-persistent"
    res = syscommand(command=command)
    if len(res) > 0:
        for line in res:
            if ver in line:
                val = line.split("boolean")[1].strip().rstrip()
                return val.capitalize()
    else:
        return None

def set_autosave_debconf() -> None:
    """
    Setting iptables-persistent autosave values in debconf database (values from config).
    :return:
    """
    a_v4 = debconf_autosave_value(ver='v4')
    if a_v4 != str(config.SAVE_V4_RULES_ON_REBOOT):
        log.info("Preconfiguring iptables-persistent ...")
        val = "iptables-persistent iptables-persistent/autosave_v4 boolean " + str(config.SAVE_V4_RULES_ON_REBOOT).lower()
        log.info("Setting autosave option for ipv4 iptables rules to " + str(config.SAVE_V4_RULES_ON_REBOOT))
        insert_to_debconf(value=val)
    a_v6 = debconf_autosave_value(ver='v6')
    if a_v6 != str(config.SAVE_V6_RULES_ON_REBOOT):
        val = "iptables-persistent iptables-persistent/autosave_v6 boolean " + str(config.SAVE_V6_RULES_ON_REBOOT).lower()
        log.info("Setting autosave option for ipv6 iptables rules to " + str(config.SAVE_V6_RULES_ON_REBOOT))
        insert_to_debconf(value=val)


def install_package(package: str) -> None:
    """
    Install any package
    """
    command = "apt update && "
    syscommand(command)
    command = "apt install -y " + package
    syscommand(command)


def package_present(package_name) -> bool:
    """
    Checking for package present
    :return:    True or False
    """
    command = "dpkg -s " + package_name + " | grep Status"
    result = syscommand(command)
    parts = result[0].split(":")
    result = parts[1].strip()
    if result == "install ok installed":
        return True
    else:
        return False

def package_major_version(package_name) -> int or bool:
    """
    :return:    major version of installed package
    """
    command = "dpkg -s " + package_name + " | grep Version"
    result = syscommand(command)
    if result:
        if "Version" in result[0]:
            parts = result[0].split(":")
            result = parts[1].strip()
            version = result.split("-")[0]
            version = version.split(".")[0]
            return int(version)
        else:
            return False


def check_sys_packages_exist() -> None:
    """
    Checking for necessary packages
    """
    log.info("Looking for required packages ...")
    packages_to_install = sys_packages
    if len(config.AMNEZIA_GEO_RESTRICT) > 0 or len(config.SSH_GEO_RESTRICT) > 0:
        for geo_pack in geo_packages:
            packages_to_install.append(geo_pack)
    for package in packages_to_install:
        if package_present(package_name=package) is False:
            log.info("Required package '" + package + "' not found! Trying to install")
            install_package(package=package)
            if package_present(package_name=package) is True:
                log.info("Package '" + package + "' successfully installed")
            else:
                log.critical("Can't install package '" + package + "'! Reboot and try again!")
                raise SystemExit
        else:
            log.debug("Required package '" + package + "' present")
    log.info("All required packages installed!")

def check_misc_packages_exist() -> None:
    """
    Checking for additional packages
    """
    packages_to_install = config.MISC_PACKAGES
    if len(packages_to_install) > 0:
        for package in packages_to_install:
            if package_present(package_name=package) is False:
                log.info("Additional package '" + package + "' not found! Trying to install")
                install_package(package=package)
                if package_present(package_name=package) is True:
                    log.info("Package '" + package + "' successfully installed")
            else:
                log.debug("Additional package '" + package + "' present")

if __name__ == '__main__':
    set_autosave_debconf()
    check_sys_packages_exist()
    check_misc_packages_exist()

