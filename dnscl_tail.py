#!/usr/bin/env python3

# dnscl: Analyze BIND DNS query data from syslog file input
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

"""This program analyzes BIND DNS queries from syslog input."""
import sys
import timeit
from collections import defaultdict
import re
import argparse
import subprocess
from typing import DefaultDict, List

__author__ = "Mark W. Hunter"
__version__ = "0.58-tail"
FILENAME = "/var/log/syslog"  # path to syslog file
# FILENAME = "/var/log/messages"  # path to alternate syslog file


def dnscl_ipaddress(
    ip_address: str,
    filename: str = FILENAME,
    domain_search: str = "",
    tail_num: int = 0,
    quiet_mode: bool = False,
) -> int:
    """Return a domain name queried by a client IP address."""
    start_time = timeit.default_timer()
    domain_dict: DefaultDict = defaultdict(int)
    line_count = 0
    ip_address_search = ip_address + "#"

    if tail_num:
        syslog = tail(filename, tail_num)
    else:
        syslog = tail(filename)

    for line in syslog:
        line = line.decode("utf-8")
        if ip_address_search in line and "named" in line and "query" in line:
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

    print(f"{ip_address} total queries: {line_count}")
    print("queries: ")

    for domain_name, query_count in domain_list_sorted:
        print(f"{query_count} \t {domain_name}")

    if not quiet_mode:
        print(
            f"\nSummary: Searched {ip_address} and found {line_count}",
            f"queries for {len(domain_dict)} domain names.",
        )
        print(f"Query time: {round(elapsed_time, 2)} seconds")
    return line_count


def dnscl_domain(
    domain_name: str,
    filename: str = FILENAME,
    ip_search: str = "",
    tail_num: int = 0,
    quiet_mode: bool = False,
) -> int:
    """Return client IP addresses that queried a domain name."""
    start_time = timeit.default_timer()
    ip_dict: DefaultDict = defaultdict(int)
    domain_list = []
    line_count = 0

    if tail_num:
        syslog = tail(filename, tail_num)
    else:
        syslog = tail(filename)

    for line in syslog:
        line = line.decode("utf-8")
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

    print(f"{domain_name} total queries: {line_count}")
    print("ip addresses: ")

    for ip_address, query_count in ip_list_sorted:
        print(f"{query_count} \t {ip_address}")

    if domain_name:
        print("\ndomain names: ")
        for domain_names_found in domain_set:
            print(domain_names_found)
        if not quiet_mode:
            print(
                f"\nSummary: Searched {domain_name} and found {line_count}",
                f"queries for {len(domain_set)} domain names from {len(ip_dict)} clients.",
            )
            print(f"Query time: {round(elapsed_time, 2)} seconds")
    else:
        if not quiet_mode:
            print(
                f"\nSummary: Searched {domain_name} and found {line_count}",
                f"queries from {len(ip_dict)} clients.",
            )
            print(f"Query time: {round(elapsed_time, 2)} seconds")
    return line_count


def dnscl_rpz(
    ip_address: str,
    filename: str = FILENAME,
    tail_num: int = 0,
    quiet_mode: bool = False,
) -> int:
    """Return rpz names queried by a client IP address."""
    start_time = timeit.default_timer()
    rpz_dict: DefaultDict = defaultdict(int)
    line_count = 0
    ip_address_search = ip_address + "#"

    if tail_num:
        syslog = tail(filename, tail_num)
    else:
        syslog = tail(filename)

    for line in syslog:
        line = line.decode("utf-8")
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

    print(f"{ip_address} total queries: {line_count}")
    print("queries: ")

    for domain_name, query_count in rpz_list_sorted:
        print(query_count, "\t", domain_name)

    if not quiet_mode:
        print(
            f"\nSummary: Searched {ip_address} and found {line_count}",
            f"queries for {len(rpz_dict)} rpz names.",
        )
        print(f"Query time: {round(elapsed_time, 2)} seconds")
    return line_count


def dnscl_rpz_domain(
    domain_rpz_name: str,
    filename: str = FILENAME,
    tail_num: int = 0,
    quiet_mode: bool = False,
) -> int:
    """Return client IP addresses that queried a rpz domain name."""
    start_time = timeit.default_timer()
    rpz_ip_dict: DefaultDict = defaultdict(int)
    rpz_domain_list = []
    line_count = 0

    if tail_num:
        syslog = tail(filename, tail_num)
    else:
        syslog = tail(filename)

    for line in syslog:
        line = line.decode("utf-8")
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

    print(f"{domain_rpz_name} total queries: {line_count}")
    print("ip addresses: ")

    for ip_address, query_count in rpz_ip_list_sorted:
        print(query_count, "\t", ip_address)

    if domain_rpz_name:
        print("\nrpz names: ")

        for domain_names_found in rpz_domain_set:
            print(domain_names_found)

    if not quiet_mode:
        print(
            f"\nSummary: Searched {domain_rpz_name} and found {line_count}",
            f"queries from {len(rpz_ip_dict)} clients.",
        )
        print(f"Query time: {round(elapsed_time, 2)} seconds")
    return line_count


def dnscl_record_ip(
    ip_address: str,
    filename: str = FILENAME,
    tail_num: int = 0,
    quiet_mode: bool = False,
) -> int:
    """Return record types queried by a client IP address."""
    start_time = timeit.default_timer()
    record_dict: DefaultDict = defaultdict(int)
    domain_list = []
    line_count = 0
    ip_address_search = ip_address + "#"

    if tail_num:
        syslog = tail(filename, tail_num)
    else:
        syslog = tail(filename)

    for line in syslog:
        line = line.decode("utf-8")
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

    print(f"{ip_address} total queries: {line_count}")
    print("queries: ")

    for record_type, query_count in record_list_sorted:
        print(query_count, "\t", record_type)

    if ip_address:
        print("\ndomain names: ")
        for domain_names_found in sorted(set(domain_list)):
            print(domain_names_found)

    if not quiet_mode:
        print(
            f"\nSummary: Searched {ip_address} and found {line_count}",
            f"queries with {len(set(record_dict))} record types for {len(set(domain_list))}",
            "domains.",
        )
        print(f"Query time: {round(elapsed_time, 2)} seconds")
    return line_count


def dnscl_record_domain(
    domain_name: str,
    filename: str = FILENAME,
    tail_num: int = 0,
    quiet_mode: bool = False,
) -> int:
    """Return record types for a queried domain name."""
    start_time = timeit.default_timer()
    record_dict: DefaultDict = defaultdict(int)
    ip_list = []
    domain_list = []
    line_count = 0

    if tail_num:
        syslog = tail(filename, tail_num)
    else:
        syslog = tail(filename)

    for line in syslog:
        line = line.decode("utf-8")
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

    print(f"{domain_name} total queries: {line_count}")
    print("record types: ")

    for record_type, query_count in record_list_sorted:
        print(query_count, "\t", record_type)

    if domain_name:
        print("\ndomain names: ")
        for domain_names_found in sorted(set(domain_list)):
            print(domain_names_found)

        print("\nip addresses: ")
        for ip_addresses_found in sorted(set(ip_list)):
            print(ip_addresses_found)

    if not quiet_mode:
        print(
            f"\nSummary: Searched {domain_name} and found {line_count}",
            f"queries for {len(record_dict)} record types from {len(set(ip_list))} clients.",
        )
        print(f"Query time: {round(elapsed_time, 2)} seconds")
    return line_count


def dnscl_record_type(
    record_type: str,
    filename: str = FILENAME,
    tail_num: int = 0,
    quiet_mode: bool = False,
) -> int:
    """Return domain names of a particular record type."""
    start_time = timeit.default_timer()
    record_domain_dict: DefaultDict = defaultdict(int)
    record_ip_list = []
    line_count = 0

    if tail_num:
        syslog = tail(filename, tail_num)
    else:
        syslog = tail(filename)

    for line in syslog:
        line = line.decode("utf-8")
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

    print(f"record type {record_type.upper()} total queries: {line_count}")
    print("queries: ")

    for domain_name, query_count in record_domain_list_sorted:
        print(query_count, "\t", domain_name)

    print("\nip addresses: ")
    for ip_addresses_found in set(record_ip_list):
        print(ip_addresses_found)

    if not quiet_mode:
        print(
            f"\nSummary: Searched record type {record_type.upper()} and found",
            f"{line_count} queries for",
            f"{len(record_domain_dict)} domains from",
            f"{len(set(record_ip_list))} clients.",
        )
        print("Query time:", str(round(elapsed_time, 2)), "seconds")
    return line_count


def find_domain_field(fields: List[str]):
    """Find and return domain field value."""
    field_index = 0
    for field in fields:
        if field == "query:":
            field_value = fields[field_index + 1]
            return field_value
        field_index += 1
    return None


def find_ip_field(fields: List[str]):
    """Find and return ip field value."""
    field_index = 0
    for field in fields:
        if field == "query:":
            field_value = fields[field_index - 2]
            return field_value
        field_index += 1
    return None


def find_rpz_domain_field(fields: List[str]):
    """Find and return rpz domain field."""
    field_index = 0
    for field in fields:
        if field == "QNAME":
            field_value = fields[field_index + 3]
            return field_value
        field_index += 1
    return None


def find_rpz_ip_field(fields: List[str]):
    """Find and return rpz ip field value."""
    field_index = 0
    for field in fields:
        if field == "QNAME":
            field_value = fields[field_index - 3]
            return field_value
        field_index += 1
    return None


def find_record_type_field(fields: List[str]):
    """Find and return record type field."""
    field_index = 0
    for field in fields:
        if field == "query:":
            field_value = fields[field_index + 3]
            return field_value
        field_index += 1
    return None


def sort_dict(dict_unsorted: DefaultDict) -> List:
    """Sort dictionary by values in reverse order."""
    list_sorted = sorted(
        dict_unsorted.items(), key=lambda dict_sort: dict_sort[1], reverse=True
    )
    return list_sorted


def tail(filename: str, num_lines: int = 60):
    """Returns n number of last lines from input file."""
    proc = subprocess.Popen(
        ["tail", "-n", str(num_lines), filename], stdout=subprocess.PIPE
    )
    assert proc.stdout is not None
    lines = proc.stdout.readlines()
    return lines


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Run dnscl_tail.py -h for help.")
    else:
        WILDCARD = ""
        dnscl_parser = argparse.ArgumentParser(
            description="Analyze BIND DNS query data from syslog file input"
        )
        dnscl_subparser = dnscl_parser.add_subparsers(title="commands", dest="command")
        parser_ip = dnscl_subparser.add_parser(
            "ip", help="domains queried by an ip address"
        )
        parser_domain = dnscl_subparser.add_parser(
            "domain", help="ip addresses that queried a domain"
        )
        parser_rpz = dnscl_subparser.add_parser("rpz", help="rpz domains queried")
        parser_type = dnscl_subparser.add_parser("type", help="record types queried")
        parser_ip.add_argument("-i", help="ip address", default=WILDCARD)
        parser_ip.add_argument("-d", help="domain", default=WILDCARD)
        parser_ip.add_argument("-f", "--file", help="filename", default=FILENAME)
        parser_ip.add_argument("-n", help="lines to tail", type=int, default=0)
        parser_ip.add_argument("-q", "--quiet", help="quiet mode", action="store_true")
        parser_domain.add_argument("-d", help="domain", default=WILDCARD)
        parser_domain.add_argument("-i", help="ip address", default=WILDCARD)
        parser_domain.add_argument("-f", "--file", help="filename", default=FILENAME)
        parser_domain.add_argument("-n", help="lines to tail", default=0)
        parser_domain.add_argument(
            "-q", "--quiet", help="quiet mode", action="store_true"
        )
        parser_rpz.add_argument("-r", help="rpz domain", default=WILDCARD)
        parser_rpz.add_argument("-f", "--file", help="filename", default=FILENAME)
        parser_rpz.add_argument("-n", help="lines to tail", default=0)
        parser_rpz.add_argument("-q", "--quiet", help="quiet mode", action="store_true")
        parser_type.add_argument("-t", help="record type", default=WILDCARD)
        parser_type.add_argument("-f", "--file", help="filename", default=FILENAME)
        parser_type.add_argument("-n", help="lines to tail", default=0)
        parser_type.add_argument(
            "-q", "--quiet", help="quiet mode", action="store_true"
        )
        dnscl_parser.add_argument(
            "-v",
            "--version",
            action="version",
            version="%(prog)s " + __version__ + ", " + __author__ + " (c) 2020",
        )
        args = dnscl_parser.parse_args()

        if args.command == "ip":
            dnscl_ipaddress(args.i, args.file, args.d, args.n, args.quiet)
        elif args.command == "domain":
            dnscl_domain(args.d, args.file, args.i, args.n, args.quiet)
        elif args.command == "rpz":
            if args.r == WILDCARD:
                dnscl_rpz(args.r, args.file, args.n, args.quiet)
            else:
                dnscl_rpz_domain(args.r, args.file, args.n, args.quiet)
        elif args.command == "type":
            if args.t == WILDCARD:
                dnscl_record_domain(args.t, args.file, args.n, args.quiet)
            else:
                dnscl_record_type(args.t, args.file, args.n, args.quiet)
