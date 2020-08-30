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
from itertools import groupby
import timeit
import socket
# import argparse
import re

AUTHOR = "Mark W. Hunter"
VERSION = "0.45-pihole"
FILENAME = "/var/log/pihole.log"


def dnscl_ipaddress(ip_address):
    """Returns domain names queried by a client IP address."""
    start_time = timeit.default_timer()
    domain_list = []
    line_count = 0
    with open(FILENAME, encoding="UTF-8") as piholelog:
        for line in piholelog:
            field_index = 0
            if "query[" in line:
                fields = line.strip().split(" ")
                if ip_address:
                    ip_field = find_field(
                        fields, field_index, "ip_address"
                    )
                    if ip_field == ip_address:
                        domain_list.append(
                            find_field(fields, field_index, "domain")
                        )
                        line_count += 1
                else:
                    domain_list.append(
                        find_field(fields, field_index, "domain")
                    )
                    line_count += 1

    domain_list_final = [
        (len(list(dcount)), dname) for dname, dcount in groupby(sorted(domain_list))
    ]
    domain_list_final.sort(reverse=True)
    unique_domains = len(sorted(set(domain_list)))
    elapsed_time = timeit.default_timer() - start_time

    print(f"{ip_address} total queries: {line_count}")
    print("queries: ")

    for query_count, domain_name in domain_list_final:
        print(f"{query_count}\t {domain_name}")

    print(
        f"\nSummary: Searched {ip_address} and found {line_count}",
        f"queries for {unique_domains} domain names.",
    )
    print(f"Query time: {round(elapsed_time, 2)} seconds")


def dnscl_domain(domain_name):
    """Returns client IP addresses that queried a domain name."""
    start_time = timeit.default_timer()
    ip_list = []
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
                    ip_list.append(ip_address)
                    if domain_name:
                        domain_list.append(domain_name_field)
                    line_count += 1

    ip_list_final = [
        (len(list(dcount)), dname) for dname, dcount in groupby(sorted(ip_list))
    ]
    ip_list_final.sort(reverse=True)
    unique_clients = len(sorted(set(ip_list)))
    elapsed_time = timeit.default_timer() - start_time

    print(f"{domain_name} total queries: {line_count}")
    print("ip addresses: ")

    for query_count, ip_address in ip_list_final:
        print(f"{query_count}\t {ip_address}")

    if domain_name:
        print("\ndomain names: ")
        for domain_names_found in sorted(set(domain_list)):
            print(domain_names_found)
        print(
            f"\nSummary: Searched {domain_name} and found {line_count}",
            f"queries for {len(set(domain_list))} domain names from {unique_clients} clients.",
        )
    else:
        print(
            f"\nSummary: Searched {domain_name} and found {line_count}",
            f"queries from {unique_clients} clients.",
        )
    print(f"Query time: {round(elapsed_time, 2)} seconds")


def dnscl_blocklist(ip_address):
    """Returns blocklist names queried by a client IP address."""
    start_time = timeit.default_timer()
    block_list = []
    line_count = 0

    with open(FILENAME, encoding="UTF-8") as piholelog:
        for line in piholelog:
            field_index = 0
            if ip_address in line:
                if "is 0.0.0.0" in line:
                    fields = line.strip().split(" ")
                    block_list.append(
                        find_field(fields, field_index, "block_domain")
                    )
                    line_count += 1

    block_list_final = [
        (len(list(dcount)), dname) for dname, dcount in groupby(sorted(block_list))
    ]
    block_list_final.sort(reverse=True)
    unique_block_domains = len(sorted(set(block_list)))
    elapsed_time = timeit.default_timer() - start_time

    print(f"{ip_address} total queries: {line_count}")
    print("queries: ")

    for query_count, domain_name in block_list_final:
        print(f"{query_count}\t {domain_name}")

    print(
        f"\nSummary: Searched {ip_address} and found {line_count}",
        f"queries for {unique_block_domains} blocklist names.",
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
    elif sys.argv[1] == "ip" and len(sys.argv) == 3:
        if sys.argv[2] == "--all" or sys.argv[2] == "-a":
            WILDCARD = ""
            dnscl_ipaddress(WILDCARD)
        elif is_valid_ipv4_address(sys.argv[2]):
            dnscl_ipaddress(sys.argv[2])
        elif is_valid_ipv6_address(sys.argv[2]):
            dnscl_ipaddress(sys.argv[2])
        else:
            print("Invalid ip address, try again.")
    elif sys.argv[1] == "domain" and len(sys.argv) == 3:
        if sys.argv[2] == "--all" or sys.argv[2] == "-a":
            WILDCARD = ""
            dnscl_domain(WILDCARD)
        else:
            dnscl_domain(sys.argv[2])
    elif sys.argv[1] == "blocklist" and len(sys.argv) == 3:
        if sys.argv[2] == "--all" or sys.argv[2] == "-a":
            WILDCARD = ""
            dnscl_blocklist(WILDCARD)
        else:
            dnscl_blocklist(sys.argv[2])
    elif sys.argv[1] == "--version" or sys.argv[1] == "-v":
        print("dnscl version:", VERSION)
    elif sys.argv[1] == "--help" or sys.argv[1] == "-h":
        print("Usage: dnscl [OPTION] ...")
        print("\nRun without options for interactive menu. Valid options include:")
        print(
            "\n ip <ip_address> \t Returns domain names queried by a client IP address"
        )
        print(
            " ip --all, -a \t\t Returns all domain names queried by any client IP address"
        )
        print(" domain <domain>\t Returns client IP addresses that queried a domain")
        print(
            " domain --all, -a \t Returns all client IP addresses that queried any domain"
        )
        print(
            " blocklist <domain>\t Returns client IP addresses that queried a blocked domain"
        )
        print(
            " blocklist --all, -a \t Returns all client IP addresses that "
            "queried any blocked domain"
        )
        print(" --version, -v\t\t Display version information and exit")
        print(" --help, -h\t\t Display this help text and exit\n")
        print(f"dnscl {VERSION}, {AUTHOR} (c) 2020\n")
    else:
        print("Error, try again.")
