#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import config
from parse import parse_timeout
from dsrLogger import logger as log
from misc import \
    syscommand, \
    replace_string_in_file, \
    insert_to_index_of_file, \
    index_of_line_contains, \
    check_string_in_file


config = config.Config()

def create_rclocal_file() -> None:
    """
    Creating executable rc.local file for script autorun on reboot
    :return:
    """
    log.info("Processing rc.local file...")
    with open(config.RC_LOCAL_FILE, 'w') as rc:
        rc.write(
            "#!/bin/bash\n"
            "sleep " + str(config.RC_LOCAL_RUN_TIMEOUT) + "\n"
            "/usr/bin/python3 " + config.MAIN_DIR + "/check_amnezia_rules.py > /dev/null 2>&1\n"
            "exit 0\n"
        )
        command = "chmod +x " + config.RC_LOCAL_FILE
        syscommand(command=command)


def create_rclocal_unit() -> None:
    """
    Creating rc.local unit for autorun any script specified in /etc/rc.local
    :return:
    """
    log.info("Creating rc.local systemd unit..")
    with open(config.RC_LOCAL_UNIT_FILE, 'w') as unit:
        unit.write(
            "[Unit]\n"
            "Description=/etc/rc.local Compatibility\n"
            "ConditionPathExists=" + config.RC_LOCAL_FILE + "\n\n"
            "[Service]\n"
            "Type=forking\n"
            "ExecStart=" + config.RC_LOCAL_FILE + " start\n"
            "TimeoutSec=0\n"
            "StandardOutput=tty\n"
            "RemainAfterExit=yes\n\n"
            "[Install]\n"
            "WantedBy=multi-user.target\n"
        )
    command = "systemctl daemon-reload"
    syscommand(command)
    command = "systemctl enable " + config.RC_LOCAL_UNIT_NAME
    syscommand(command)
    command = "systemctl start " + config.RC_LOCAL_UNIT_NAME
    syscommand(command)

def check_rclocal_unit() -> bool:
    """
    Check if exist rclocal systemd unit
    :return:    True of False
    """
    command = "systemctl list-units | grep " + config.RC_LOCAL_UNIT_NAME
    res = syscommand(command)
    if res:
        return True
    else:
        return False

def rclocal_timeout() -> str or bool:
    """
    Getting current run timeout for scripts specified in rc.local file
    :return:        timeout value or False if not found
    """
    with open(config.RC_LOCAL_FILE, 'r') as rc:
        found = False
        for line in rc:
            if "sleep" in line:
                found = True
                timeout = parse_timeout(string=line)
    if found is True:
        return timeout
    else:
        return False


def configure_rclocal() -> None:
    """
    Configuring rc.local service and autorun file
    """
    log.info("Checking for rc-local systemd unit ...")
    # если rc.local не найден
    if not os.path.exists(path=config.RC_LOCAL_FILE):
        create_rclocal_file()
    else:
        timeout = rclocal_timeout()
        if timeout is not False:
            if timeout != str(config.RC_LOCAL_RUN_TIMEOUT):
                old_val = "sleep " + str(timeout)
                new_val = "sleep " + str(config.RC_LOCAL_RUN_TIMEOUT)
                replace_string_in_file(file=config.RC_LOCAL_FILE, old_val=old_val, new_val=new_val)
                log.info("Setting new rc.local timeout value to '" + str(config.RC_LOCAL_RUN_TIMEOUT) + "' seconds..")
        else:
            line_to_add = "sleep " + str(config.RC_LOCAL_RUN_TIMEOUT)
            insert_to_index_of_file(file_to_insert=config.RC_LOCAL_FILE, string_to_insert=line_to_add, ind=1)
        sleep_ind = index_of_line_contains(file_for_search=config.RC_LOCAL_FILE, string_to_search='sleep')
        line_to_find = "/usr/bin/python3 " + config.MAIN_DIR + "/check_amnezia_rules.py > /dev/null 2>&1"
        check_string_in_file(s_file=config.RC_LOCAL_FILE, string_to_check=line_to_find, ind=sleep_ind)
    if check_rclocal_unit() is False:
        create_rclocal_unit()
    log.info("rc-local looks good!")


if __name__ == '__main__':
    configure_rclocal()
