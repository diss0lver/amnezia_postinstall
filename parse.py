#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re

def find(pattern: str, text: str) -> list or bool:
    """
    Find by regular expressions
    :param text           the text object for search
    :param pattern        search pattern
    """
    match = re.findall(pattern, text)
    if match:
        return match
    return False

def parse_country_set(string: str) -> list or bool:
    """
    Parsing country zone (such as 'ru' or 'tm') from iptables rule
    :param string:
    :return:        country zone or False if not found
    """
    pat = (r''
           '--match-set\s'
           '(\D+)\s'
           'src\s'
           )
    data = find(pat, string)
    if data is False:
        return False
    return data[0].strip()


def parse_ip(string: str) -> list or bool:
    """
    Parsing an ip address
    :param string:      string for search
    :return:            ip address or False if not found
    """
    pat = (r''
           '\d+.\d+.\d+.\d+'
        )
    data = find(pat, string)
    if data is False:
        return False
    return data[0].strip()


def parse_cidr(string: str):
    pat = (r''
        '\d+.\d+.\d+.\d+/\d+'
    )
    data = find(pat, string)
    if data is False:
        return False
    return data[0].strip()

def parse_ip_from_route(string: str):
    pat = (r''
           'src(\s\d+.\d+.\d+.\d+)'
           )
    data = find(pat, string)
    if data is False:
        return False
    return data[0].strip()


def parse_rule(string: str):
    pat = (r''
           '(DOCKER-USER|INPUT)\s'
           '(.+)'
           '\s(--comment)\s'
           '(.+)\s'
           '-j'
           )
    data = find(pat, string)
    if data is False:
        return False
    return data[0]

def parse_timeout(string: str):
    pat = (r''
           'sleep\s'
           '(\d+)'
    )
    data = find(pat, string)
    if data is False:
        return False
    return data[0]
