#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import config
from dsrLogger import logger as log
from misc import \
    syscommand, \
    find_bin, \
    ip_in_subnetwork
from parse import \
    parse_ip, \
    parse_cidr, \
    parse_ip_from_route, \
    parse_issue

docker_bin = find_bin(bin_file='docker')
config = config.Config()

def detected_amnezia_containers() -> list or bool:
    """
    Detecting running amnezia docker containers
    :return:            list of running amnezia containers
    """
    if docker_bin is not False:
        containers = []
        command = docker_bin + " ps"
        cont = syscommand(command)
        for line in cont:
            if config.AMNEZIA_CONT_MARKER in line:
                container = line[line.find(config.AMNEZIA_CONT_MARKER):]
                container = container.split(" ")[0]
                containers.append(container)
                log.debug("Container " + container + " detected")
        if len(containers) > 0:
            return containers
        else:
            return False
    else:
        return False


def container_id(cont_name: str) -> str or bool:
    """
    Getting id of container by its name
    :param cont_name:       container name, such as amnezia-openvpn
    :return:
    """
    cont_id = False
    command = docker_bin + " inspect --format=\"{{.Id}}\" " + cont_name
    res = syscommand(command=command)
    if res:
        if "Error" in res[0]:   # container has never been installed
            return False
        elif ":" in res[0]:     # container was removed
            return False
        else:
            cont_id = res[0]    # container exist
            log.debug("Id for container " + cont_name + " is " + cont_id[:20] + "....")
    return cont_id


def cont_name_by_id(cont_id: str) -> str:
    """
    Getting name of docker container by it id
    :param cont_id:     container id for search
    :return:            container name
    """
    command = docker_bin + " inspect --format=\"{{.Name}}\" " + cont_id
    res = syscommand(command=command)
    if res:
        cont_name = res[0].replace("/", "")
        return cont_name
    else:
        log.critical("No name detected for container " + cont_id[:20])
        raise SystemExit


def container_exposed_ports(container: str) -> list:
    """
    :param container:       docker container name for detect ports
    :return:                list or ports [1194/udp, 6789/tcp]
    """
    command = docker_bin + " inspect --format='{{json .Config}}' " + container
    res = syscommand(command)
    result_ports = []
    if res:
        for line in res:
            cont_config = json.loads(line)
            try:
                ports = cont_config["ExposedPorts"]
                for port in ports:
                    result_ports.append(port)
            except KeyError as err:
                log.debug(err)
    return result_ports


def stop_docker_container(cont_id: str) -> None:
    """
    Stopping docker container
    :param cont_id: container id, such as d2a90e40c32cbe8175539813f8c08c1b17177c7386a840442c7a1a4ea0aadfe8
    :return:
    """
    command = docker_bin + " stop " + cont_id
    res = syscommand(command=command)
    if res:
        try:
            if res[0] == cont_id:
                cont_name = cont_name_by_id(cont_id=cont_id)
                log.info("Container " + cont_name + " stopped")
        except IndexError as err:
            log.error(err)


def start_docker_container(cont_id: str) -> None:
    """
    Starting docker container
    :param cont_id: container id, such as d2a90e40c32cbe8175539813f8c08c1b17177c7386a840442c7a1a4ea0aadfe8
    :return:
    """
    command = docker_bin + " start " + cont_id
    res = syscommand(command=command)
    if res:
        try:
            if res[0] == cont_id:
                cont_name = cont_name_by_id(cont_id=cont_id)
                log.info("Container " + cont_name + " started")
        except IndexError as err:
            log.error(err)


def restart_docker_service() -> None:
    """
    Restarting docker service
    :return:
    """
    command = 'systemctl restart docker'
    res = syscommand(command=command)
    if not res:
        log.info("Service docker restarted")
    else:
        log.error(res[0])

def container_log_type(cont_id: str) -> str:
    """
    Getting current container log type
    :param cont_id:         container id, such as d2a90e40c32cbe8175539813f8c08c1b17177c7386a840442c7a1a4ea0aadfe8
    :return:
    """
    # cont_conf = "/var/lib/docker/containers/" + cont_id + "/hostconfig.json"
    cont_conf = config.DOCKER_CONT_PATH + "/" + cont_id + "/" + config.DOCKER_HOSTCONF_FILE
    with open(cont_conf, 'r') as c:
        conf = json.load(c)
        log_type = conf['LogConfig']['Type']
        if log_type != 'none':
            cont_name = cont_name_by_id(cont_id=cont_id)
            log.info("Log type of container " + cont_name + " is '" + log_type + "'")
        return log_type


def disable_container_log(cont_id: str) -> None:
    """
    Switching off container json logging
    :param cont_id:
    :return:
    """
    cont_name = cont_name_by_id(cont_id=cont_id)
    log.info("Trying to change log type of container " + cont_name + " ...")
    cont_conf = config.DOCKER_CONT_PATH + "/" + cont_id + "/" + config.DOCKER_HOSTCONF_FILE
    with open(cont_conf, 'r') as c:
        conf = json.load(c)
        conf['LogConfig']['Type'] = 'none'
    with open(cont_conf, 'w') as cw:
        cw.truncate(0)
        cw.write(json.dumps(conf))

def container_default_route(container: str) -> str or bool:
    """
    :param container:   container to search route
    :return:            default route ip address of False if not
    """
    command = docker_bin + " exec  " + container + " /sbin/ip route|awk '/default/ { print $3 }'"
    res = syscommand(command)
    if res:
        route = parse_ip(res[0])
        return route
    else:
        return False


def container_cidr_list(container: str) -> list:
    """
    :param container:   container to search
    :return:            list of subnetworks from routing table
    """
    cidr_list = []
    command = docker_bin + " exec " + container + " ip route"
    res = syscommand(command=command)
    if res:
        for line in res:
            cidr = parse_cidr(string=line)
            if cidr is not False:
                cidr_list.append(cidr)
    return cidr_list


def container_ipaddresses(container: str) -> list:
    """
    :param container:   container to search
    :return:            list of ip addresses from routing table
    """
    ip_list = []
    command = docker_bin + " exec " + container + " ip route"
    res = syscommand(command=command)
    if res:
        for line in res:
            ip = parse_ip_from_route(string=line)
            if ip is not False:
                ip_list.append(ip)
    return ip_list


def container_default_cidr(def_route: str, cidr_list: list) -> str:
    """
    :param def_route:   default route ip address of container
    :param cidr_list:   list of subnetworks from container routing table
    :return:            subnetwork which default route ip address belongs
    """
    for cidr in cidr_list:
        if ip_in_subnetwork(ip_address=def_route, subnetwork=cidr) is True:
            return cidr

def container_default_ip(ip_list: list, cidr: str) -> str:
    """
    :param ip_list:     list of ip addresses from container routing table
    :param cidr:        subnetwork which default route ip address belongs
    :return:            default container ip address
    """
    for ip in ip_list:
        if ip_in_subnetwork(ip_address=ip, subnetwork=cidr) is True:
            return ip

def find_cont_ip_by_default_route(container: str) -> str:
    """
    Searching for default container ip address by default container route ip address
    :param container:   container for search
    :return:            container default ip address
    """
    def_route = container_default_route(container=container)
    cidr_list = container_cidr_list(container=container)
    cont_ip_list = container_ipaddresses(container=container)
    def_cidr = container_default_cidr(def_route=def_route, cidr_list=cidr_list)
    ip = container_default_ip(ip_list=cont_ip_list, cidr=def_cidr)
    return ip


def cont_without_ip(cont_list: list) -> list:
    """
    Searching containers without iproute2 package installed
    :param cont_list:   list of all containers
    :return:            list of containers without iproute2
    """
    c_list = []
    for cont in cont_list:
        ip = find_cont_ip_by_default_route(container=cont)
        if ip is None:
            c_list.append(cont)
    return c_list


def container_issue(cont_name: str) -> str or bool:
    """
    :param cont_name:   container name for request
    :return:            issue of container OS (Debian, Alpine, etc)
    """
    command = "docker exec " + cont_name + " cat /etc/issue"
    res = syscommand(command=command)
    issue = False
    if res:
        for line in res:
            issue = parse_issue(string=line)
            if issue is not False:
                return issue
    return issue

def container_install_bin(issue: str) -> tuple or bool:
    """
    :param issue:       issue of container OS (Debian, Alpine, etc)
    :return:            binary for install packages
    """
    if issue == 'Alpine':
        return 'apk', 'add'
    elif issue == 'Debian' or issue == 'Ubuntu':
        return 'apt', 'install -y'
    else:
        return False



def install_iproute2_in_container(container: str, inst_bin: tuple) -> None:
    """
    Installing iproute2 package to container
    :param container:   container to install
    :param inst_bin:    apt for Debian or apk for Alpine
    """
    binary, action = inst_bin
    log.info("Installing missed necessary 'iproute2' package to " + container + " container...")
    command = docker_bin + " exec " + container + " " + binary + " update"
    syscommand(command=command)
    command = docker_bin + " exec " + container + " " + binary + " " + action + " iproute2"
    syscommand(command=command)


def configure_container_packages() -> None:
    """
    Checking all containers for iproute2 package installed.
    Install it if absent
    :return:
    """
    log.info("Checking containers for required packages...")
    containers = detected_amnezia_containers()
    cont_w_ip = cont_without_ip(cont_list=containers)
    if len(cont_w_ip) > 0:
        for cont in cont_w_ip:
            cont_issue = container_issue(cont_name=cont)
            cont_install_bin = container_install_bin(issue=cont_issue)
            if cont_install_bin is not False:
                install_iproute2_in_container(container=cont, inst_bin=cont_install_bin)
            else:
                log.error("Unsupported container image!")
    log.info("All containers are checked!")

def replace_file_in_container(cont_id: str, file_to_replace: str, new_file: str) -> None:
    """
    Replacing specified file in container with backup
    :param cont_id:             id of container
    :param file_to_replace:     file, which will be replaced
    :param new_file:            new file
    """
    command = docker_bin + " exec " + cont_id + " mv " + file_to_replace + " " + file_to_replace + ".bak"
    syscommand(command=command)
    command = docker_bin + " cp " + new_file + " " + cont_id + ":" + file_to_replace
    syscommand(command=command)
    stop_docker_container(cont_id=cont_id)
    start_docker_container(cont_id=cont_id)


def set_containers_logging_off():
    """
    Disable json logging for all amnezia containers
    :return:
    """
    if config.DISABLE_DOCKER_JSON_LOG is True:
        log.info("Configuring logging options for docker containers ...")
        cont_list = []      # список контейнеров с типом лога отличным от none
        containers = detected_amnezia_containers()
        for container in containers:
            cont_id = container_id(cont_name=container)
            if container_log_type(cont_id=cont_id) != 'none':
                cont_list.append(cont_id)
        # если найдены контейнеры с включенным логом
        if len(cont_list) > 0:
            for cont_id in cont_list:
                # останавливаем контейнер и меняем на none
                stop_docker_container(cont_id=cont_id)
                disable_container_log(cont_id=cont_id)
            # перезапускаем docker
            restart_docker_service()
            # запускаем контейнеры
            for cont_id in cont_list:
                start_docker_container(cont_id=cont_id)
        log.info("All containers are processed!")

if __name__ == '__main__':
    set_containers_logging_off()


