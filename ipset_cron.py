#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from ipset import create_ipset_lists
from misc import merged_geo_list

country_list = merged_geo_list()

if __name__ == '__main__':
    create_ipset_lists(countries=country_list)

