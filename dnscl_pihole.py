#!/usr/bin/env python3

# dnscl: Analyze Pi-hole DNS query data from log file input
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

"""This program analyzes Pi-hole DNS queries from log input."""
import sys
from collections import defaultdict
import timeit
import socket
import argparse
import re

__author__ = "Mark W. Hunter"
__version__ = "0.48-pihole"
FILENAME = "/var/log/pihole.log"


def dnscl_ipaddress(ip_address):
    """Returns domain names queried by a client IP address."""
    start_time = timeit.default_timer()
    domain_dict = defaultdict(int)
    line_count = 0
    with open(FILENAME, encoding="UTF-8") as piholelog:
        for line in piholelog:
            field_index = 0
            if "query[" in line:
                fields = line.strip().split(" ")
                domain_name_field = find_field(fields, field_index, "domain")
                if ip_address:
                    ip_field = find_field(
                        fields, field_index, "ip_address"
                    )
                    if ip_field == ip_address:
                        domain_dict[domain_name_field] += 1
                        line_count += 1
                else:
                    domain_dict[domain_name_field] += 1
                    line_count += 1

    domain_list_sorted = sort_dict(domain_dict)
    elapsed_time = timeit.default_timer() - start_time

    print(f"{ip_address} total queries: {line_count}")
    print("queries: ")

    for domain_name, query_count in domain_list_sorted:
        print(f"{query_count}\t {domain_name}")

    print(
        f"\nSummary: Searched {ip_address} and found {line_count}",
        f"queries for {len(domain_dict)} domain names.",
    )
    print(f"Query time: {round(elapsed_time, 2)} seconds")


def dnscl_domain(domain_name):
    """Returns client IP addresses that queried a domain name."""
    start_time = timeit.default_timer()
    ip_dict = defaultdict(int)
    domain_list = []
    line_count = 0

    with open(FILENAME, encoding="UTF-8") as piholelog:
        for line in piholelog:
            field_index = 0
            if "query[" in line:
                fields = line.strip().split(" ")
                domain_name_field = find_field(fields, field_index, "domain")
                ip_address = find_field(fields, field_index, "ip_address")
                if re.search(domain_name, domain_name_field, re.IGNORECASE):
                    ip_dict[ip_address] += 1
                    if domain_name:
                        domain_list.append(domain_name_field)
                    line_count += 1

    ip_list_sorted = sort_dict(ip_dict)
    elapsed_time = timeit.default_timer() - start_time

    print(f"{domain_name} total queries: {line_count}")
    print("ip addresses: ")

    for ip_address, query_count in ip_list_sorted:
        print(f"{query_count}\t {ip_address}")

    if domain_name:
        print("\ndomain names: ")
        for domain_names_found in sorted(set(domain_list)):
            print(domain_names_found)
        print(
            f"\nSummary: Searched {domain_name} and found {line_count}",
            f"queries for {len(set(domain_list))} domain names from {len(ip_dict)} clients.",
        )
    else:
        print(
            f"\nSummary: Searched {domain_name} and found {line_count}",
            f"queries from {len(ip_dict)} clients.",
        )
    print(f"Query time: {round(elapsed_time, 2)} seconds")


def dnscl_blocklist(block_list_name):
    """Returns blocklist names queried by a client IP address."""
    start_time = timeit.default_timer()
    block_list_dict = defaultdict(int)
    line_count = 0

    with open(FILENAME, encoding="UTF-8") as piholelog:
        for line in piholelog:
            field_index = 0
            if block_list_name in line:
                if "is 0.0.0.0" in line:
                    fields = line.strip().split(" ")
                    block_list_field = find_field(fields, field_index, "block_domain")
                    block_list_dict[block_list_field] += 1
                    line_count += 1

    block_list_sorted = sort_dict(block_list_dict)
    elapsed_time = timeit.default_timer() - start_time

    print(f"{block_list_name} total queries: {line_count}")
    print("queries: ")

    for domain_name, query_count in block_list_sorted:
        print(f"{query_count}\t {domain_name}")

    print(
        f"\nSummary: Searched {block_list_name} and found {line_count}",
        f"queries for {len(block_list_dict)} blocklist names.",
    )
    print(f"Query time: {round(elapsed_time, 2)} seconds")


def is_valid_ipv4_address(address):
    """Checks input is a valid IPv4 address."""
    try:
        socket.inet_pton(socket.AF_INET, address)
    except socket.error:
        return False
    return True


def is_valid_ipv6_address(address):
    """Checks input is a valid IPv6 address."""
    try:
        socket.inet_pton(socket.AF_INET6, address)
    except socket.error:
        return False
    return True


def find_field(fields, field_index, field_type):
    """Find and return requested field value."""
    if field_type == "domain":
        for field in fields:
            if "query[" in field:
                field_value = fields[field_index + 1]
                return field_value
            field_index += 1
    elif field_type == "ip_address":
        for field in fields:
            if "query[" in field:
                field_value = fields[field_index + 3]
                return field_value
            field_index += 1
    elif field_type == "block_domain":
        for field in fields:
            if "0.0.0.0" in field:
                field_value = fields[field_index - 2]
                return field_value
            field_index += 1
    return None


def sort_dict(dict_unsorted):
    """Sort dictionary by values in reverse order."""
    dict_sorted = sorted(
        dict_unsorted.items(), key=lambda dict_sort: dict_sort[1], reverse=True
    )
    return dict_sorted


def menu():
    """Prints main menu."""
    print("\ndnscl Menu (Pi-hole version)\n")
    print("Enter 0 to exit")
    print("Enter 1 to search ip address")
    print("Enter 2 to search domain name")
    print("Enter 3 to search blocklist name")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        while True:
            menu()
            CHOICE = input("=> ")
            while not CHOICE.isdigit():
                print("Invalid input, try again.")
                menu()
                CHOICE = input("=> ")
            try:
                int(CHOICE)
            except ValueError:
                print("Invalid input, exiting.")
                break
            if int(CHOICE) == 1:
                IP = input("ip address: ")
                if IP:
                    while not is_valid_ipv4_address(IP) and not is_valid_ipv6_address(IP):
                        print("Invalid ip address, try again.")
                        IP = input("ip address: ")
                dnscl_ipaddress(IP)
            elif int(CHOICE) == 2:
                DOMAIN = input("domain name: ")
                dnscl_domain(DOMAIN)
            elif int(CHOICE) == 3:
                IP = input("blocklist name: ")
                dnscl_blocklist(IP)
            elif int(CHOICE) > 3:
                print("Invalid choice, try again.")
            elif int(CHOICE) == 0:
                break
    else:
        wildcard = ""
        dnscl_parser = argparse.ArgumentParser(
            description="Analyze Pi-hole DNS query data from log file input"
        )
        dnscl_subparser = dnscl_parser.add_subparsers(title="commands", dest="command")
        parser_ip = dnscl_subparser.add_parser(
            "ip", help="domains queried by an ip address"
        )
        parser_domain = dnscl_subparser.add_parser(
            "domain", help="ip addresses that queried a domain"
        )
        parser_blocklist = dnscl_subparser.add_parser(
            "blocklist", help="blocklist domains queried"
        )
        parser_ip.add_argument("-i",
                               help="ip address",
                               default=wildcard)
        parser_domain.add_argument("-d",
                                   help="domain",
                                   default=wildcard)
        parser_blocklist.add_argument("-b",
                                      help="blocklist name",
                                      default=wildcard)
        dnscl_parser.add_argument("-v",
                                  "--version",
                                  action="version",
                                  version="%(prog)s "
                                          + __version__ + ", "
                                          + __author__ + " (c) 2020")
        args = dnscl_parser.parse_args()

        if args.command == "ip":
            dnscl_ipaddress(args.i)
        elif args.command == "domain":
            dnscl_domain(args.d)
        elif args.command == "blocklist":
            if args.b == wildcard:
                dnscl_blocklist(args.b)
            else:
                dnscl_blocklist(args.b)
