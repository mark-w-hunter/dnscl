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

"""This program analyzes DNS queries from syslog input"""
import sys
from itertools import groupby
import timeit
# from pyfiglet import print_figlet

AUTHOR = "Mark W. Hunter"
VERSION = "0.45"
FILENAME = "/var/log/syslog"  # path to syslog file
# FILENAME = "/var/log/messages"  # path to syslog file


def dnscl_ipaddress(ip_address):
    """Returns domain names queried by a client IP address"""
    start_time = timeit.default_timer()
    domain_list = []
    line_count = 0
    ip_address_search = ip_address + "#"

    for line in open(FILENAME, encoding="ISO-8859-1"):
        if ip_address_search in line:
            if "named" in line and "query:" in line:
                fields = line.strip().split(" ")
                if len(fields) > 12:
                    domain_list.append(find_domain_field(fields))  # find domain
                    line_count += 1

    domain_set = sorted(set(domain_list))
    domain_list_final = [
        (len(list(dcount)), dname) for dname, dcount in groupby(
            sorted(domain_list))
    ]
    domain_list_final.sort(reverse=True)
    elapsed_time = timeit.default_timer() - start_time

    print(f"{ip_address} total queries: {line_count}")
    print("queries: ")

    for query_count, domain_name in domain_list_final:
        print(query_count, "\t", domain_name)

    print(
        f"\nSummary: Searched {ip_address} and found {line_count}",
        f"queries for {len(domain_set)} domain names.",
    )
    print(f"Query time: {round(elapsed_time, 2)} seconds")


def dnscl_domain(domain_name):
    """Returns client IP addresses that queried a domain name"""
    start_time = timeit.default_timer()
    ip_list = []
    domain_list = []
    line_count = 0

    for line in open(FILENAME, encoding="ISO-8859-1"):
        if domain_name.lower() in line.lower() and "query:" in line:
            fields = line.strip().split(" ")
            ip_address = find_ip_field(fields).split("#")  # find ip
            ip_list.append(ip_address[0])
            if domain_name != "" and domain_name.lower() in find_domain_field(fields):
                domain_list.append(find_domain_field(fields))  # find domain
            line_count += 1

    ip_set = sorted(set(ip_list))
    domain_set = sorted(set(domain_list))
    ip_list_final = [
        (len(list(dcount)), dname) for dname, dcount in groupby(
            sorted(ip_list))
    ]
    ip_list_final.sort(reverse=True)
    elapsed_time = timeit.default_timer() - start_time

    print(f"{domain_name} total queries: {line_count}")
    print("ip addresses: ")

    for query_count, ip_address in ip_list_final:
        print(query_count, "\t", ip_address)

    if domain_name != "":
        print("\ndomain names: ")
        for domain_names_found in domain_set:
            print(domain_names_found)
        print(
            f"\nSummary: Searched {domain_name} and found {line_count}",
            f"queries for {len(domain_set)} domain names from {len(ip_set)} clients.",
        )
    else:
        print(
            f"\nSummary: Searched {domain_name} and found {line_count}",
            f"queries from {len(ip_set)} clients."
        )
    print(f"Query time: {round(elapsed_time, 2)} seconds")


def dnscl_rpz(ip_address):
    """Returns rpz names queried by a client IP address"""
    start_time = timeit.default_timer()
    rpz_list = []
    line_count = 0
    ip_address_search = ip_address + "#"

    for line in open(FILENAME, encoding="ISO-8859-1"):
        if ip_address_search in line:
            if "QNAME" in line and "SOA" not in line:
                fields = line.strip().split(" ")
                if len(fields) > 11:
                    rpz_list.append(find_rpz_domain_field(fields))  # find rpz domain
                    line_count += 1

    rpz_set = sorted(set(rpz_list))
    rpz_list_final = [
        (len(list(dcount)), dname) for dname, dcount in groupby(
            sorted(rpz_list))
    ]
    rpz_list_final.sort(reverse=True)
    elapsed_time = timeit.default_timer() - start_time

    print(f"{ip_address} total queries: {line_count}")
    print("queries: ")

    for query_count, domain_name in rpz_list_final:
        print(query_count, "\t", domain_name)

    print(
        f"\nSummary: Searched {ip_address} and found {line_count}",
        f"queries for {len(rpz_set)} rpz names.",
    )
    print(f"Query time: {round(elapsed_time, 2)} seconds")


def dnscl_rpz_domain(domain_rpz_name):
    """Returns client IP addresses that queried a rpz domain name"""
    start_time = timeit.default_timer()
    rpz_ip_list = []
    rpz_domain_list = []
    line_count = 0

    for line in open(FILENAME, encoding="ISO-8859-1"):
        if domain_rpz_name in line:
            if "QNAME" in line and "SOA" not in line:
                fields = line.strip().split(" ")
                if domain_rpz_name.lower() in line.lower() and len(fields) > 11:
                    ip_address = find_rpz_ip_field(fields).split("#")  # find rpz ip
                    rpz_ip_list.append(ip_address[0])
                    if domain_rpz_name != "":
                        rpz_domain_list.append(find_rpz_domain_field(fields))  # find rpz domain
                    line_count += 1

    rpz_ip_set = sorted(set(rpz_ip_list))
    rpz_domain_set = sorted(set(rpz_domain_list))
    rpz_ip_list_final = [
        (len(list(dcount)), dname) for dname, dcount in groupby(
            sorted(rpz_ip_list))
    ]
    rpz_ip_list_final.sort(reverse=True)
    elapsed_time = timeit.default_timer() - start_time

    print(f"{domain_rpz_name} total queries: {line_count}")
    print("ip addresses: ")

    for query_count, ip_address in rpz_ip_list_final:
        print(query_count, "\t", ip_address)

    if domain_rpz_name != "":
        print("\nrpz names: ")

        for domain_names_found in rpz_domain_set:
            print(domain_names_found)

    print(
        f"\nSummary: Searched {domain_rpz_name} and found {line_count}",
        f"queries from {len(rpz_ip_set)} clients.",
    )
    print(f"Query time: {round(elapsed_time, 2)} seconds")


def dnscl_record_ip(ip_address):
    """Returns record types queried by a client IP address"""
    start_time = timeit.default_timer()
    record_list = []
    domain_list = []
    line_count = 0
    ip_address_search = ip_address + "#"

    for line in open(FILENAME, encoding="ISO-8859-1"):
        if ip_address_search in line:
            if "query:" in line:
                fields = line.strip().split(" ")
                if len(fields) > 12:
                    record_list.append(
                        find_record_type_field(fields))  # find record type
                    domain_list.append(find_domain_field(fields))  # find domain
                    line_count += 1

    record_list_final = [
        (len(list(dcount)), dname) for dname, dcount in groupby(
            sorted(record_list))
    ]
    record_list_final.sort(reverse=True)
    elapsed_time = timeit.default_timer() - start_time

    print(f"{ip_address} total queries: {line_count}")
    print("queries: ")

    for query_count, record_type in record_list_final:
        print(query_count, "\t", record_type)

    if ip_address != "":
        print("\ndomain names: ")
        for domain_names_found in sorted(set(domain_list)):
            print(domain_names_found)

    print(
        f"\nSummary: Searched {ip_address} and found {line_count}",
        f"queries with {len(set(record_list))} record types for {len(set(domain_list))}",
        f"domains.",
    )
    print(f"Query time: {round(elapsed_time, 2)} seconds")


def dnscl_record_domain(domain_name):
    """Returns record types for a queried domain name"""
    start_time = timeit.default_timer()
    ip_list = []
    domain_list = []
    record_list = []
    line_count = 0

    for line in open(FILENAME, encoding="ISO-8859-1"):
        fields = line.strip().split(" ")
        if domain_name.lower() in line.lower() and "query:" in line:
            ip_address = find_ip_field(fields).split("#")  # ip
            ip_list.append(ip_address[0])
            record_list.append(find_record_type_field(fields))  # find record type
            if domain_name != "":
                domain_list.append(find_domain_field(fields))  # find domain
            line_count += 1

    record_list_final = [
        (len(list(dcount)), dname) for dname, dcount in groupby(
            sorted(record_list))
    ]
    record_list_final.sort(reverse=True)
    elapsed_time = timeit.default_timer() - start_time

    print(f"{domain_name} total queries: {line_count}")
    print("record types: ")

    for query_count, record_type in record_list_final:
        print(query_count, "\t", record_type)

    if domain_name != "":
        print("\ndomain names: ")
        for domain_names_found in sorted(set(domain_list)):
            print(domain_names_found)

        print("\nip addresses: ")
        for ip_addresses_found in sorted(set(ip_list)):
            print(ip_addresses_found)

    print(
        f"\nSummary: Searched {domain_name} and found {line_count}",
        f"queries for {len(set(record_list))} record types from {len(set(ip_list))} clients.",
    )
    print(f"Query time: {round(elapsed_time, 2)} seconds")


def dnscl_record_type(record_type):
    """Returns domain names of a particular record type"""
    start_time = timeit.default_timer()
    record_domain_list = []
    record_ip_list = []
    line_count = 0

    for line in open(FILENAME, encoding="ISO-8859-1"):
        if "query:" in line:
            fields = line.strip().split(" ")
            if record_type.upper() in find_record_type_field(fields):  # find record type
                record_domain_list.append(find_domain_field(fields))  # find domain
                ip_address = find_ip_field(fields).split("#")  # find ip
                record_ip_list.append(ip_address[0])
                line_count += 1

    record_domain_list_final = [
        (len(list(dcount)), dname) for dname, dcount in groupby(
            sorted(record_domain_list))
    ]
    record_domain_list_final.sort(reverse=True)
    elapsed_time = timeit.default_timer() - start_time

    print(f"record type {record_type.upper()} total queries: {line_count}")
    print("queries: ")

    for query_count, domain_name in record_domain_list_final:
        print(query_count, "\t", domain_name)

    print("\nip addresses: ")
    for ip_addresses_found in set(record_ip_list):
        print(ip_addresses_found)

    print(
        f"\nSummary: Searched record type {record_type.upper()} and found",
        f"{line_count} queries for",
        f"{len(set(record_domain_list))} domains from",
        f"{len(set(record_ip_list))} clients.",
    )
    print("Query time:", str(round(elapsed_time, 2)), "seconds")


def find_domain_field(fields):
    """Find and return domain field value"""
    field_index = 0
    for field in fields:
        if field == "query:":
            field_value = fields[field_index + 1]  # find domain field
            return field_value.lower()
        field_index += 1
    return None


def find_ip_field(fields):
    """Find and return ip field value"""
    field_index = 0
    for field in fields:
        if field == "query:":
            field_value = fields[field_index - 2]  # find ip field
            return field_value
        field_index += 1
    return None


def find_rpz_domain_field(fields):
    """Find and return rpz domain field"""
    field_index = 0
    for field in fields:
        if field == "QNAME":
            field_value = fields[field_index + 3]  # find rpz domain field
            return field_value
        field_index += 1
    return None


def find_rpz_ip_field(fields):
    """Find and return rpz ip field value"""
    field_index = 0
    for field in fields:
        if field == "QNAME":
            field_value = fields[field_index - 3]  # find rpz ip field
            return field_value
        field_index += 1
    return None


def find_record_type_field(fields):
    """Find and return record type field"""
    field_index = 0
    for field in fields:
        if field == "query:":
            field_value = fields[field_index + 3]  # find record type
            return field_value
        field_index += 1
    return None


def menu():
    """Prints main menu"""
    print("\nDnscl Menu:\n")
    # print_figlet("Dnscl", font="ogre", colors="BLUE")
    print("Enter 0 to exit")
    print("Enter 1 to search ip")
    print("Enter 2 to search domain")
    print("Enter 3 to search rpz ip")
    print("Enter 4 to search rpz domain")
    print("Enter 5 to search ip by record type")
    print("Enter 6 to search domain by record type")
    print("Enter 7 to search record type details")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        while True:
            menu()
            CHOICE = input("=> ")
            while not CHOICE.isdigit():
                print("Invalid input, try again.")
                menu()
                CHOICE = input("=> ")
            if int(CHOICE) == 1:
                IP = input("ip address: ")
                dnscl_ipaddress(IP)
            elif int(CHOICE) == 2:
                DOMAIN = input("domain name: ")
                dnscl_domain(DOMAIN)
            elif int(CHOICE) == 3:
                IP = input("rpz ip: ")
                dnscl_rpz(IP)
            elif int(CHOICE) == 4:
                DOMAIN = input("rpz domain name: ")
                dnscl_rpz_domain(DOMAIN)
            elif int(CHOICE) == 5:
                IP = input("ip address: ")
                dnscl_record_ip(IP)
            elif int(CHOICE) == 6:
                DOMAIN = input("domain: ")
                dnscl_record_domain(DOMAIN)
            elif int(CHOICE) == 7:
                TYPE = input("record type: ")
                dnscl_record_type(TYPE)
            elif int(CHOICE) > 7:
                print("Invalid choice, try again.")
            elif int(CHOICE) == 0:
                break
    elif sys.argv[1] == "ip" and len(sys.argv) == 3:
        if sys.argv[2] == "--all" or sys.argv[2] == "-a":
            WILDCARD = ""
            dnscl_ipaddress(WILDCARD)
        else:
            dnscl_ipaddress(sys.argv[2])
    elif sys.argv[1] == "domain" and len(sys.argv) == 3:
        if sys.argv[2] == "--all" or sys.argv[2] == "-a":
            WILDCARD = ""
            dnscl_domain(WILDCARD)
        else:
            dnscl_domain(sys.argv[2])
    elif sys.argv[1] == "rpz" and len(sys.argv) == 3:
        if sys.argv[2] == "--all" or sys.argv[2] == "-a":
            WILDCARD = ""
            dnscl_rpz(WILDCARD)
        else:
            dnscl_rpz_domain(sys.argv[2])
    elif sys.argv[1] == "--version" or sys.argv[1] == "-v":
        print(f"Dnscl version: {VERSION}")
    elif sys.argv[1] == "--help" or sys.argv[1] == "-h":
        print("Usage: dnscl.py [OPTION] ...")
        print("\nRun without options for interactive menu. Valid options include:")
        print(
            "\n  ip <ip_address> or --all, -a\t Returns domains queried by an IP",
            "address or all domains",
        )
        print(
            "  domain <domain> or --all, -a\t Returns IP addresses that queried",
            "a domain or all IP addresses",
        )
        print(
            "  rpz <rpz_domain> or --all, -a\t Returns IP addresses that queried",
            "a RPZ domain or all RPZ domains",
        )
        print("  --version, -v\t\t\t Display version information and exit")
        print("  --help, -h\t\t\t Display this help text and exit\n")
        print(f"Dnscl {VERSION}, {AUTHOR} (c) 2020")
    else:
        print("Error, try again.")
