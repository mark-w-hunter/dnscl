#!/usr/bin/env python3

# dnscl: Analyze BIND DNS query data from syslog file input - Flask API version
# author: Mark W. Hunter
# https://github.com/mark-w-hunter/dnscl
#
# The MIT License (MIT)
#
# Copyright (c) 2020 Mark W. Hunter
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""Analyze BIND DNS queries from Flask web API."""
import timeit
from collections import defaultdict
import re
from typing import DefaultDict, List

__author__ = "Mark W. Hunter"
__version__ = "0.58-api"
FILENAME = "/var/log/syslog"  # path to syslog file
# FILENAME = "/var/log/messages"  # path to alternate syslog file


def dnscl_ipaddress(ip_address: str, domain_search: str = "") -> str:
    """Return a domain name queried by a client IP address.

    Args:
        ip_address (str): IP address to search.
        domain_search (str, optional): Domain name to search. Defaults to "".

    Returns:
        str: Search results found.

    """
    start_time = timeit.default_timer()
    domain_dict: DefaultDict = defaultdict(int)
    line_count = 0
    ip_address_search = ip_address + "#"
    results = ""

    with open(FILENAME, encoding="ISO-8859-1") as syslog:
        for line in syslog:
            if ip_address_search in line:
                if "named" in line and "query:" in line:
                    fields = line.strip().split(" ")
                    if len(fields) > 12:
                        domain = find_domain_field(fields)
                        if domain_search:
                            if re.search(domain_search, domain, re.IGNORECASE):
                                domain_dict[domain] += 1
                                line_count += 1
                        else:
                            domain_dict[domain] += 1
                            line_count += 1

    domain_list_sorted = sort_dict(domain_dict)
    elapsed_time = timeit.default_timer() - start_time
    results += f"{ip_address} total queries: {line_count}\n"
    results += f"queries: \n"

    for domain_name, query_count in domain_list_sorted:
        results += f"{query_count} \t {domain_name}\n"

    results += f"\nSummary: Searched {ip_address} and found {line_count} "
    results += f"queries for {len(domain_dict)} domain names.\n"
    results += f"Query time: {round(elapsed_time, 2)} seconds\n"
    return results


def dnscl_domain(domain_name: str, ip_search: str = "") -> str:
    """Return client IP addresses that queried a domain name.

    Args:
        domain_name (str): Domain name to search.
        ip_search (str, optional): IP address to search. Defaults to "".

    Returns:
        str: Search results found.

    """
    start_time = timeit.default_timer()
    ip_dict: DefaultDict = defaultdict(int)
    domain_list = []
    line_count = 0
    results = ""

    with open(FILENAME, encoding="ISO-8859-1") as syslog:
        for line in syslog:
            if "query:" in line:
                fields = line.strip().split(" ")
                ip_address_field = find_ip_field(fields).split("#")
                ip_address = ip_address_field[0]
                domain_name_field = find_domain_field(fields)
                if re.search(domain_name, domain_name_field, re.IGNORECASE):
                    if ip_search:
                        if ip_search in line:
                            ip_dict[ip_address] += 1
                            domain_list.append(domain_name_field)
                            line_count += 1
                    else:
                        ip_dict[ip_address] += 1
                        domain_list.append(domain_name_field)
                        line_count += 1

    ip_list_sorted = sort_dict(ip_dict)
    domain_set = sorted(set(domain_list))
    elapsed_time = timeit.default_timer() - start_time

    results += f"{domain_name} total queries: {line_count}\n"
    results += f"queries: \n"

    for ip_address, query_count in ip_list_sorted:
        results += f"{query_count} \t {ip_address}\n"

    if domain_name:
        results += f"\ndomain names:\n"
        for domain_names_found in domain_set:
            results += f"{domain_names_found}\n"
        results += f"\nSummary: Searched {domain_name} and found {line_count} queries "
        results += f"for {len(domain_set)} domain names from {len(ip_dict)} clients.\n"
        results += f"Query time: {round(elapsed_time, 2)} seconds\n"
    else:
        results += f"\nSummary: Searched {domain_name} and found {line_count} "
        results += f"queries from {len(ip_dict)} clients.\n"
        results += f"Query time: {round(elapsed_time, 2)} seconds\n"
    return results


def dnscl_rpz(ip_address: str) -> str:
    """Return RPZ names queried by a client IP address.

    Args:
        ip_address (str): IP address to search.

    Returns:
        str: Search results found.

    """
    start_time = timeit.default_timer()
    rpz_dict: DefaultDict = defaultdict(int)
    line_count = 0
    ip_address_search = ip_address + "#"
    results = ""

    with open(FILENAME, encoding="ISO-8859-1") as syslog:
        for line in syslog:
            if ip_address_search in line:
                if "QNAME" in line and "SOA" not in line:
                    fields = line.strip().split(" ")
                    rpz_domain_fields = find_rpz_domain_field(fields).split("/")
                    rpz_domain = rpz_domain_fields[0]
                    if len(fields) > 11:
                        rpz_dict[rpz_domain] += 1
                        line_count += 1

    rpz_list_sorted = sort_dict(rpz_dict)
    elapsed_time = timeit.default_timer() - start_time

    results += f"{ip_address} total queries: {line_count}\n"
    results += f"queries: \n"

    for domain_name, query_count in rpz_list_sorted:
        results += f"{query_count} \t {domain_name}\n"

    results += f"\nSummary: Searched {ip_address} and found {line_count} "
    results += f"queries for {len(rpz_dict)} domain names.\n"
    results += f"Query time: {round(elapsed_time, 2)} seconds\n"
    return results


def dnscl_rpz_domain(domain_rpz_name: str) -> str:
    """Return client IP addresses that queried a RPZ domain name.

    Args:
        domain_rpz_name (str): RPZ domain name to search.

    Returns:
        int: Number of queries found.

    """
    start_time = timeit.default_timer()
    rpz_ip_dict: DefaultDict = defaultdict(int)
    rpz_domain_list = []
    line_count = 0
    results = ""

    with open(FILENAME, encoding="ISO-8859-1") as syslog:
        for line in syslog:
            if domain_rpz_name in line:
                if "QNAME" in line and "SOA" not in line:
                    fields = line.strip().split(" ")
                    if domain_rpz_name.lower() in line.lower() and len(fields) > 11:
                        ip_address_field = find_rpz_ip_field(fields).split("#")
                        ip_address = ip_address_field[0]
                        rpz_domain_fields = find_rpz_domain_field(fields).split("/")
                        rpz_domain = rpz_domain_fields[0]
                        rpz_ip_dict[ip_address] += 1
                        if domain_rpz_name:
                            rpz_domain_list.append(rpz_domain)
                        line_count += 1

    rpz_ip_list_sorted = sort_dict(rpz_ip_dict)
    rpz_domain_set = sorted(set(rpz_domain_list))
    elapsed_time = timeit.default_timer() - start_time

    results += f"{domain_rpz_name} total queries: {line_count}\n"
    results += f"ip addresses: \n"

    for ip_address, query_count in rpz_ip_list_sorted:
        results += f"{query_count} \t {ip_address}\n"

    if domain_rpz_name:
        results += f"\nrpz names:\n"

        for domain_names_found in rpz_domain_set:
            results += f"{domain_names_found}\n"

    results += f"\nSummary: Searched {domain_rpz_name} and found {line_count} "
    results += f"queries from {len(rpz_ip_dict)} clients.\n"
    results += f"Query time: {round(elapsed_time, 2)} seconds\n"
    return results


def dnscl_record_ip(ip_address: str) -> str:
    """Return record types queried by a client IP address.

    Args:
        ip_address (str): IP address to search.

    Returns:
        str: Search results found.

    """
    start_time = timeit.default_timer()
    record_dict: DefaultDict = defaultdict(int)
    domain_list = []
    line_count = 0
    ip_address_search = ip_address + "#"
    results = ""

    with open(FILENAME, encoding="ISO-8859-1") as syslog:
        for line in syslog:
            if ip_address_search in line:
                if "query:" in line:
                    fields = line.strip().split(" ")
                    record_type = find_record_type_field(fields)
                    if len(fields) > 12:
                        record_dict[record_type] += 1
                        domain_list.append(find_domain_field(fields))
                        line_count += 1

    record_list_sorted = sort_dict(record_dict)
    elapsed_time = timeit.default_timer() - start_time

    results += f"{ip_address} total queries: {line_count}\n"
    results += f"queries: \n"

    for record_type, query_count in record_list_sorted:
        results += f"{query_count} \t {record_type}\n"

    if ip_address:
        results += f"\ndomain names: \n"
        for domain_names_found in sorted(set(domain_list)):
            results += f"{domain_names_found}\n"

    results += f"\nSummary: Searched {ip_address} and found {line_count} "
    results += "qqueries with {len(set(record_dict))} record types for {len(set(domain_list))} "
    results += "domains.\n"
    results += f"Query time: {round(elapsed_time, 2)} seconds\n"
    return results


def dnscl_record_domain(domain_name: str) -> str:
    """Return record types for a queried domain name.

    Args:
        domain_name (str): Domain name to search.

    Returns:
        str: Search results found.

    """
    start_time = timeit.default_timer()
    record_dict: DefaultDict = defaultdict(int)
    ip_list = []
    domain_list = []
    line_count = 0
    results = ""

    with open(FILENAME, encoding="ISO-8859-1") as syslog:
        for line in syslog:
            fields = line.strip().split(" ")
            if domain_name.lower() in line.lower() and "query:" in line:
                ip_address = find_ip_field(fields).split("#")
                ip_list.append(ip_address[0])
                record_type = find_record_type_field(fields)
                record_dict[record_type] += 1
                if domain_name:
                    domain_list.append(find_domain_field(fields))
                line_count += 1

    record_list_sorted = sort_dict(record_dict)
    elapsed_time = timeit.default_timer() - start_time

    results += f"{domain_name} total queries: {line_count}\n"
    results += f"record types: \n"

    for record_type, query_count in record_list_sorted:
        results += f"{query_count} \t {record_type}\n"

    if domain_name:
        results += f"\ndomain names:\n"
        for domain_names_found in sorted(set(domain_list)):
            results += f"{domain_names_found}\n"

        results += f"\nip addresses: \n"
        for ip_addresses_found in sorted(set(ip_list)):
            results += f"{ip_addresses_found}\n"

    results += f"\nSummary: Searched {domain_name} and found {line_count} "
    results += f"queries for {len(record_dict)} record types from {len(set(ip_list))} clients.\n"
    results += f"Query time: {round(elapsed_time, 2)} seconds\n"
    return results


def dnscl_record_type(record_type: str) -> str:
    """Return domain names of a particular record type.

    Args:
        record_type (str): Record type to search.

    Returns:
        str: Search results found.

    """
    start_time = timeit.default_timer()
    record_domain_dict: DefaultDict = defaultdict(int)
    record_ip_list = []
    line_count = 0
    results = ""

    with open(FILENAME, encoding="ISO-8859-1") as syslog:
        for line in syslog:
            if "query:" in line:
                fields = line.strip().split(" ")
                if record_type.upper() == find_record_type_field(fields):
                    record_domain = find_domain_field(fields)
                    record_domain_dict[record_domain] += 1
                    ip_address = find_ip_field(fields).split("#")
                    record_ip_list.append(ip_address[0])
                    line_count += 1

    record_domain_list_sorted = sort_dict(record_domain_dict)
    elapsed_time = timeit.default_timer() - start_time

    results += f"record type {record_type.upper()} total queries: {line_count}\n"
    results += f"queries: \n"

    for domain_name, query_count in record_domain_list_sorted:
        results += f"{query_count} \t {domain_name}\n"

    results += f"\nip addresses: \n"
    for ip_addresses_found in set(record_ip_list):
        results += f"{ip_addresses_found}\n"

    results += f"\nSummary: Searched record type {record_type.upper()} and found "
    results += f"{line_count} queries for {len(record_domain_dict)} domains from "
    results += f"{len(set(record_ip_list))} clients.\n"
    results += f"Query time: {round(elapsed_time, 2)} seconds\n"
    return results


def find_domain_field(fields: List[str]):
    """Find and return domain field value.

    Args:
        fields (List[str]): Fields from line.

    Returns:
        str: Domain name field value.

    """
    field_index = 0
    for field in fields:
        if field == "query:":
            field_value = fields[field_index + 1]
            return field_value
        field_index += 1
    return None


def find_ip_field(fields: List[str]):
    """Find and return IP address field value.

    Args:
        fields (List[str]): Fields from line.

    Returns:
        str: IP address field value.

    """
    field_index = 0
    for field in fields:
        if field == "query:":
            field_value = fields[field_index - 2]
            return field_value
        field_index += 1
    return None


def find_rpz_domain_field(fields: List[str]):
    """Find and return RPZ domain field.

    Args:
        fields (List[str]): Fields from line.

    Returns:
        str: RPZ domain name field value.

    """
    field_index = 0
    for field in fields:
        if field == "QNAME":
            field_value = fields[field_index + 3]
            return field_value
        field_index += 1
    return None


def find_rpz_ip_field(fields: List[str]):
    """Find and return RPZ IP address field value.

    Args:
        fields (List[str]): Fields from line.

    Returns:
        str: RPZ IP address field value.

    """
    field_index = 0
    for field in fields:
        if field == "QNAME":
            field_value = fields[field_index - 3]
            return field_value
        field_index += 1
    return None


def find_record_type_field(fields: List[str]):
    """Find and return record type field.

    Args:
        fields (List[str]): Fields from line.

    Returns:
        str: Record type field value.

    """
    field_index = 0
    for field in fields:
        if field == "query:":
            field_value = fields[field_index + 3]
            return field_value
        field_index += 1
    return None


def sort_dict(dict_unsorted: DefaultDict) -> List:
    """Sort dictionary by values in reverse order.

    Args:
        dict_unsorted (DefaultDict): Unsorted search reults.

    Returns:
        List: Sorted search results in descending order.

    """
    dict_sorted = sorted(
        dict_unsorted.items(), key=lambda dict_sort: dict_sort[1], reverse=True
    )
    return dict_sorted
