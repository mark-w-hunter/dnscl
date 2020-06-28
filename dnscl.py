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
# from pyfiglet import print_figlet

AUTHOR = "Mark W. Hunter"
VERSION = "0.51"
FILENAME = "/var/log/syslog"  # path to syslog file
# FILENAME = "/var/log/messages"  # path to syslog file


def dnscl_ipaddress(ip_address):
    """Return a domain name queried by a client IP address."""
    start_time = timeit.default_timer()
    domain_dict = {}
    line_count = 0
    ip_address_search = ip_address + "#"
    with open(FILENAME, encoding="ISO-8859-1") as syslog:
        for line in syslog:
            if ip_address_search in line:
                if "named" in line and "query:" in line:
                    fields = line.strip().split(" ")
                    if len(fields) > 12:
                        domain = find_domain_field(fields)
                        if domain in domain_dict.keys():
                            domain_dict[domain] += 1
                        else:
                            domain_dict[domain] = 1
                        line_count += 1

    domain_list_sorted = sort_dict(domain_dict)
    elapsed_time = timeit.default_timer() - start_time

    print(f"{ip_address} total queries: {line_count}")
    print("queries: ")

    for domain_name, query_count in domain_list_sorted:
        print(f"{query_count} \t {domain_name}")

    print(
        f"\nSummary: Searched {ip_address} and found {line_count}",
        f"queries for {len(domain_dict)} domain names.",
    )
    print(f"Query time: {round(elapsed_time, 2)} seconds")


def dnscl_domain(domain_name):
    """Return client IP addresses that queried a domain name."""
    start_time = timeit.default_timer()
    ip_dict = {}
    domain_list = []
    line_count = 0

    with open(FILENAME, encoding="ISO-8859-1") as syslog:
        for line in syslog:
            if domain_name.lower() in line.lower() and "query:" in line:
                fields = line.strip().split(" ")
                ip_address_field = find_ip_field(fields).split("#")  # find ip
                ip_address = ip_address_field[0]
                domain_name_field = find_domain_field(fields)  # find domain
                if ip_address in ip_dict.keys():
                    ip_dict[ip_address] += 1
                else:
                    ip_dict[ip_address] = 1
                if domain_name and domain_name.lower() in domain_name_field:
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
        print(
            f"\nSummary: Searched {domain_name} and found {line_count}",
            f"queries for {len(domain_set)} domain names from {len(ip_dict)} clients.",
        )
    else:
        print(
            f"\nSummary: Searched {domain_name} and found {line_count}",
            f"queries from {len(ip_dict)} clients."
        )
    print(f"Query time: {round(elapsed_time, 2)} seconds")


def dnscl_rpz(ip_address):
    """Return rpz names queried by a client IP address."""
    start_time = timeit.default_timer()
    rpz_dict = {}
    line_count = 0
    ip_address_search = ip_address + "#"
    with open(FILENAME, encoding="ISO-8859-1") as syslog:
        for line in syslog:
            if ip_address_search in line:
                if "QNAME" in line and "SOA" not in line:
                    fields = line.strip().split(" ")
                    rpz_domain_fields = find_rpz_domain_field(fields).split("/")
                    rpz_domain = rpz_domain_fields[0]
                    if len(fields) > 11:
                        if rpz_domain in rpz_dict.keys():
                            rpz_dict[rpz_domain] += 1
                        else:
                            rpz_dict[rpz_domain] = 1
                        line_count += 1

    rpz_list_sorted = sort_dict(rpz_dict)
    elapsed_time = timeit.default_timer() - start_time

    print(f"{ip_address} total queries: {line_count}")
    print("queries: ")

    for domain_name, query_count in rpz_list_sorted:
        print(query_count, "\t", domain_name)

    print(
        f"\nSummary: Searched {ip_address} and found {line_count}",
        f"queries for {len(rpz_dict)} rpz names.",
    )
    print(f"Query time: {round(elapsed_time, 2)} seconds")


def dnscl_rpz_domain(domain_rpz_name):
    """Return client IP addresses that queried a rpz domain name."""
    start_time = timeit.default_timer()
    rpz_ip_dict = {}
    rpz_domain_list = []
    line_count = 0

    with open(FILENAME, encoding="ISO-8859-1") as syslog:
        for line in syslog:
            if domain_rpz_name in line:
                if "QNAME" in line and "SOA" not in line:
                    fields = line.strip().split(" ")
                    if domain_rpz_name.lower() in line.lower() and len(fields) > 11:
                        ip_address_field = find_rpz_ip_field(fields).split("#")  # find rpz ip
                        ip_address = ip_address_field[0]
                        rpz_domain_fields = find_rpz_domain_field(fields).split("/")
                        # find rpz domain
                        rpz_domain = rpz_domain_fields[0]
                        if ip_address in rpz_ip_dict.keys():
                            rpz_ip_dict[ip_address] += 1
                        else:
                            rpz_ip_dict[ip_address] = 1
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

    print(
        f"\nSummary: Searched {domain_rpz_name} and found {line_count}",
        f"queries from {len(rpz_ip_dict)} clients.",
    )
    print(f"Query time: {round(elapsed_time, 2)} seconds")


def dnscl_record_ip(ip_address):
    """Return record types queried by a client IP address."""
    start_time = timeit.default_timer()
    record_dict = {}
    domain_list = []
    line_count = 0
    ip_address_search = ip_address + "#"

    with open(FILENAME, encoding="ISO-8859-1") as syslog:
        for line in syslog:
            if ip_address_search in line:
                if "query:" in line:
                    fields = line.strip().split(" ")
                    record_type = find_record_type_field(fields)  # find record type
                    if len(fields) > 12:
                        if record_type in record_dict.keys():
                            record_dict[record_type] += 1
                        else:
                            record_dict[record_type] = 1
                        domain_list.append(find_domain_field(fields))  # find domain
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

    print(
        f"\nSummary: Searched {ip_address} and found {line_count}",
        f"queries with {len(set(record_dict))} record types for {len(set(domain_list))}",
        "domains.",
    )
    print(f"Query time: {round(elapsed_time, 2)} seconds")


def dnscl_record_domain(domain_name):
    """Return record types for a queried domain name."""
    start_time = timeit.default_timer()
    record_dict = {}
    ip_list = []
    domain_list = []
    line_count = 0

    with open(FILENAME, encoding="ISO-8859-1") as syslog:
        for line in syslog:
            fields = line.strip().split(" ")
            if domain_name.lower() in line.lower() and "query:" in line:
                ip_address = find_ip_field(fields).split("#")  # find ip
                ip_list.append(ip_address[0])
                record_type = find_record_type_field(fields)  # find record type
                if record_type in record_dict.keys():
                    record_dict[record_type] += 1
                else:
                    record_dict[record_type] = 1
                if domain_name:
                    domain_list.append(find_domain_field(fields))  # find domain
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

    print(
        f"\nSummary: Searched {domain_name} and found {line_count}",
        f"queries for {len(record_dict)} record types from {len(set(ip_list))} clients.",
    )
    print(f"Query time: {round(elapsed_time, 2)} seconds")


def dnscl_record_type(record_type):
    """Return domain names of a particular record type."""
    start_time = timeit.default_timer()
    record_domain_dict = {}
    record_ip_list = []
    line_count = 0

    with open(FILENAME, encoding="ISO-8859-1") as syslog:
        for line in syslog:
            if "query:" in line:
                fields = line.strip().split(" ")
                if record_type.upper() in find_record_type_field(fields):  # find record type
                    record_domain = find_domain_field(fields)  # find domain
                    if record_domain in record_domain_dict.keys():
                        record_domain_dict[record_domain] += 1
                    else:
                        record_domain_dict[record_domain] = 1
                    ip_address = find_ip_field(fields).split("#")  # find ip
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

    print(
        f"\nSummary: Searched record type {record_type.upper()} and found",
        f"{line_count} queries for",
        f"{len(record_domain_dict)} domains from",
        f"{len(set(record_ip_list))} clients.",
    )
    print("Query time:", str(round(elapsed_time, 2)), "seconds")


def find_domain_field(fields):
    """Find and return domain field value."""
    field_index = 0
    for field in fields:
        if field == "query:":
            field_value = fields[field_index + 1]  # find domain field
            return field_value.lower()
        field_index += 1
    return None


def find_ip_field(fields):
    """Find and return ip field value."""
    field_index = 0
    for field in fields:
        if field == "query:":
            field_value = fields[field_index - 2]  # find ip field
            return field_value
        field_index += 1
    return None


def find_rpz_domain_field(fields):
    """Find and return rpz domain field."""
    field_index = 0
    for field in fields:
        if field == "QNAME":
            field_value = fields[field_index + 3]  # find rpz domain field
            return field_value
        field_index += 1
    return None


def find_rpz_ip_field(fields):
    """Find and return rpz ip field value."""
    field_index = 0
    for field in fields:
        if field == "QNAME":
            field_value = fields[field_index - 3]  # find rpz domain field
            return field_value
        field_index += 1
    return None


def find_record_type_field(fields):
    """Find and return record type field."""
    field_index = 0
    for field in fields:
        if field == "query:":
            field_value = fields[field_index + 3]  # find record type
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
    """Print main menu."""
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
