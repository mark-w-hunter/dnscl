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

"""This program analyzes Pi-hole DNS queries from log input"""
import sys
from itertools import groupby
import timeit
import socket

AUTHOR = "Mark W. Hunter"
VERSION = "0.41-pihole"
FILENAME = "/var/log/pihole.log"  # path to pihole log file


def dnscl_ipaddress(ip_address):
    """Returns domain names queried by a client IP address"""
    start_time = timeit.default_timer()
    my_list = []
    line_count = 0
    for line in open(FILENAME, encoding="UTF-8"):
        field_index = 0
        if ip_address in line:
            if "query[" in line:
                fields = line.strip().split(" ")
                my_list.append(
                    find_field(fields, field_index, "domain")
                )  # find field containing domain name
                line_count += 1

    my_list_final = [
        (len(list(dcount)), dname) for dname, dcount in groupby(sorted(my_list))
    ]
    my_list_final.sort(reverse=True)
    unique_domains = len(sorted(set(my_list)))
    elapsed_time = timeit.default_timer() - start_time

    print(f"{ip_address} total queries: {line_count}")
    print("queries: ")

    for query_count, domain_name in my_list_final:
        print(f"{query_count}\t {domain_name}")

    print(
        f"\nSummary: Searched {ip_address} and found {line_count}",
        f"queries for {unique_domains} domain names.",
    )
    print(f"Query time: {round(elapsed_time, 2)} seconds")


def dnscl_domain(domain_name):
    """Returns client IP addresses that queried a domain name"""
    start_time = timeit.default_timer()
    my_list = []
    my_domain_list = []
    line_count = 0

    for line in open(FILENAME, encoding="UTF-8"):
        field_index = 0
        if domain_name.lower() in line.lower() and "query[" in line:
            fields = line.strip().split(" ")
            my_list.append(
                find_field(fields, field_index, "ip_address")
            )  # find field containing ip address
            if domain_name != "":
                my_domain_list.append(
                    find_field(fields, field_index, "domain")
                )  # find field containing domain name
            line_count += 1

    my_list_final = [
        (len(list(dcount)), dname) for dname, dcount in groupby(sorted(my_list))
    ]
    my_list_final.sort(reverse=True)
    unique_clients = len(sorted(set(my_list)))
    elapsed_time = timeit.default_timer() - start_time

    print(f"{domain_name} total queries: {line_count}")
    print("ip addresses: ")

    for query_count, ip_address in my_list_final:
        print(f"{query_count}\t {ip_address}")

    if domain_name != "":
        print("\ndomain names: ")

        for domain_names_found in sorted(set(my_domain_list)):
            print(domain_names_found)

    print(
        f"\nSummary: Searched {domain_name} and found {line_count}",
        f"queries from {unique_clients} clients.",
    )
    print(f"Query time: {round(elapsed_time, 2)} seconds")


def dnscl_blocklist(ip_address):
    """Returns blocklist names queried by a client IP address"""
    start_time = timeit.default_timer()
    my_list = []
    line_count = 0
    for line in open(FILENAME, encoding="UTF-8"):
        field_index = 0
        if ip_address in line:
            if "is 0.0.0.0" in line:
                fields = line.strip().split(" ")
                my_list.append(
                    find_field(fields, field_index, "block_domain")
                )  # field containing blocklist domain name
                line_count += 1

    my_list_final = [
        (len(list(dcount)), dname) for dname, dcount in groupby(sorted(my_list))
    ]
    my_list_final.sort(reverse=True)
    unique_block_domains = len(sorted(set(my_list)))
    elapsed_time = timeit.default_timer() - start_time

    print(f"{ip_address} total queries: {line_count}")
    print("queries: ")

    for query_count, domain_name in my_list_final:
        print(f"{query_count}\t {domain_name}")

    print(
        f"\nSummary: Searched {ip_address} and found {line_count}",
        f"queries for {unique_block_domains} blocklist names.",
    )
    print(f"Query time: {round(elapsed_time, 2)} seconds")


def is_valid_ipv4_address(address):
    """Checks input is a valid IPv4 address"""
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:  # no inet_pton here, sorry
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count(".") == 3
    except socket.error:  # not a valid address
        return False
    return True


def is_valid_ipv6_address(address):
    """Checks input is a valid IPv6 address"""
    try:
        socket.inet_pton(socket.AF_INET6, address)
    except socket.error:  # not a valid address
        return False
    return True


def find_field(fields, field_index, field_type):
    """Find and return requested field value"""
    if field_type == "domain":
        for field in fields:
            if "query[" in field:
                field_value = fields[field_index + 1]  # find domain field
                return field_value
            field_index += 1
    elif field_type == "ip_address":
        for field in fields:
            if "query[" in field:
                field_value = fields[field_index + 3]  # find ip field
                return field_value
            field_index += 1
    elif field_type == "block_domain":
        for field in fields:
            if "0.0.0.0" in field:
                field_value = fields[field_index - 2]  # find domain field
                return field_value
            field_index += 1


def menu():
    """ Prints main menu """
    print("\nDnscl Menu (pihole version)\n")
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
                if IP != "":
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
                break  # exit program
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
        print("Dnscl version:", VERSION)
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
        print(f"Dnscl {VERSION}, {AUTHOR} (c) 2020\n")
    else:
        print("Error, try again.")
