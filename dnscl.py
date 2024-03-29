#!/usr/bin/env python3

# dnscl: Analyze BIND DNS query data from syslog file input
# author: Mark W. Hunter
# https://github.com/mark-w-hunter/dnscl
#
# The MIT License (MIT)
#
# Copyright (c) 2021 Mark W. Hunter
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
import pathlib
import timeit
from collections import defaultdict
import re
import argparse
from typing import DefaultDict, List

# from pyfiglet import print_figlet

__author__ = "Mark W. Hunter"
__version__ = "0.63"
FILENAME = "/var/log/syslog"  # default path to syslog file
# FILENAME = "/var/log/messages"  # path to alternate syslog file


def dnscl_ipaddress(
    ip_address: str,
    filename: str,
    domain_search: str = "",
    quiet_mode: bool = False,
) -> int:
    """Return a domain name queried by a client IP address.

    Args:
        ip_address (str): IP address to search.
        filename (str): Path to syslog file.
        domain_search (str, optional): Domain name to search. Defaults to "".
        quiet_mode (bool, optional): Enable quiet mode. Defaults to False.

    Returns:
        int: Number of queries found.

    """
    start_time = timeit.default_timer()
    domain_dict: DefaultDict = defaultdict(int)
    line_count = 0
    ip_address_search = ip_address + "#"

    with open(filename, encoding="ISO-8859-1") as syslog:
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
    print_results(ip_address, line_count, domain_list_sorted)

    if not quiet_mode:
        print(
            f"\nSummary: Searched {ip_address} and found {line_count}",
            f"queries for {len(domain_dict)} domain names.",
        )
        print(f"Search time: {round(elapsed_time, 2)} seconds")
    return line_count


def dnscl_domain(
    domain_name: str,
    filename: str,
    ip_search: str = "",
    quiet_mode: bool = False,
) -> int:
    """Return client IP addresses that queried a domain name.

    Args:
        domain_name (str): Domain name to search.
        filename (str): Path to syslog file.
        ip_search (str, optional): IP address to search. Defaults to "".
        quiet_mode (bool, optional): Enable quiet mode. Defaults to False.

    Returns:
        int: Number of queries found.

    """
    start_time = timeit.default_timer()
    ip_dict: DefaultDict = defaultdict(int)
    domain_dict: DefaultDict = defaultdict(int)
    line_count = 0

    with open(filename, encoding="ISO-8859-1") as syslog:
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
                            domain_dict[domain_name_field] += 1
                            line_count += 1
                    else:
                        ip_dict[ip_address] += 1
                        domain_dict[domain_name_field] += 1
                        line_count += 1

    ip_list_sorted = sort_dict(ip_dict)
    domain_list_sorted = sort_dict(domain_dict)
    elapsed_time = timeit.default_timer() - start_time

    if domain_name:
        print_results(domain_name, line_count, ip_list_sorted, domain_list_sorted)
    else:
        print_results(domain_name, line_count, ip_list_sorted)

    if not quiet_mode:
        if domain_name:
            print(
                f"\nSummary: Searched {domain_name} and found {line_count}",
                f"queries for {len(domain_dict)} domain names",
                f"from {len(ip_dict)} clients.",
            )
        else:
            print(
                f"\nSummary: Searched {domain_name} and found {line_count}",
                f"queries from {len(ip_dict)} clients.",
            )
        print(f"Search time: {round(elapsed_time, 2)} seconds")
    return line_count


def dnscl_rpz(ip_address: str, filename: str) -> int:
    """Return RPZ names queried by a client IP address.

    Args:
        ip_address (str): IP address to search.
        filename (str): Path to syslog file.

    Returns:
        int: Number of queries found.

    """
    start_time = timeit.default_timer()
    rpz_dict: DefaultDict = defaultdict(int)
    line_count = 0
    ip_address_search = ip_address + "#"
    with open(filename, encoding="ISO-8859-1") as syslog:
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
    print_results(ip_address, line_count, rpz_list_sorted)

    print(
        f"\nSummary: Searched {ip_address} and found {line_count}",
        f"queries for {len(rpz_dict)} rpz names.",
    )
    print(f"Search time: {round(elapsed_time, 2)} seconds")
    return line_count


def dnscl_rpz_domain(domain_rpz_name: str, filename: str) -> int:
    """Return client IP addresses that queried a RPZ domain name.

    Args:
        domain_rpz_name (str): RPZ domain name to search.
        filename (str): Path to syslog file.

    Returns:
        int: Number of queries found.

    """
    start_time = timeit.default_timer()
    rpz_ip_dict: DefaultDict = defaultdict(int)
    rpz_domain_list = []
    line_count = 0

    with open(filename, encoding="ISO-8859-1") as syslog:
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
    print_results(domain_rpz_name, line_count, rpz_ip_list_sorted)

    if domain_rpz_name:
        print("\nrpz names: ")

        for domain_names_found in rpz_domain_set:
            print(domain_names_found)

    print(
        f"\nSummary: Searched {domain_rpz_name} and found {line_count}",
        f"queries from {len(rpz_ip_dict)} clients.",
    )
    print(f"Search time: {round(elapsed_time, 2)} seconds")
    return line_count


def dnscl_record_ip(ip_address: str, filename) -> int:
    """Return record types queried by a client IP address.

    Args:
        ip_address (str): IP address to search.
        filename (str): Path to syslog file.

    Returns:
        int: Number of queries found.

    """
    start_time = timeit.default_timer()
    record_dict: DefaultDict = defaultdict(int)
    domain_list = []
    line_count = 0
    ip_address_search = ip_address + "#"

    with open(filename, encoding="ISO-8859-1") as syslog:
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
    print_results(ip_address, line_count, record_list_sorted)

    if ip_address:
        print("\ndomain names: ")
        for domain_names_found in sorted(set(domain_list)):
            print(domain_names_found)

    print(
        f"\nSummary: Searched {ip_address} and found {line_count}",
        f"queries with {len(set(record_dict))} record types for {len(set(domain_list))}",
        "domains.",
    )
    print(f"Search time: {round(elapsed_time, 2)} seconds")
    return line_count


def dnscl_record_domain(domain_name: str, filename: str) -> int:
    """Return record types for a queried domain name.

    Args:
        domain_name (str): Domain name to search.
        filename (str): Path to syslog file.

    Returns:
        int: Number of queries found.

    """
    start_time = timeit.default_timer()
    record_dict: DefaultDict = defaultdict(int)
    ip_list = []
    domain_list = []
    line_count = 0

    with open(filename, encoding="ISO-8859-1") as syslog:
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
    print_results(domain_name, line_count, record_list_sorted)

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
    print(f"Search time: {round(elapsed_time, 2)} seconds")
    return line_count


def dnscl_record_type(record_type: str, filename: str) -> int:
    """Return domain names of a particular record type.

    Args:
        record_type (str): Record type to search.
        filename (str): Path to syslog file.

    Returns:
        int: Number of queries found.

    """
    start_time = timeit.default_timer()
    record_domain_dict: DefaultDict = defaultdict(int)
    record_ip_list = []
    line_count = 0

    with open(filename, encoding="ISO-8859-1") as syslog:
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
    print_results(record_type.upper(), line_count, record_domain_list_sorted)

    print("\nip addresses: ")
    for ip_addresses_found in set(record_ip_list):
        print(ip_addresses_found)

    print(
        f"\nSummary: Searched record type {record_type.upper()} and found",
        f"{line_count} queries for",
        f"{len(record_domain_dict)} domains from",
        f"{len(set(record_ip_list))} clients.",
    )
    print("Search time:", str(round(elapsed_time, 2)), "seconds")
    return line_count


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


def print_results(search: str, count: int, *results_arg: List):
    """Print formatted results from search.

    Args:
        search (str): Term searched.
        count (int): Number of results found.
        results_arg (List): Sorted search results.

    Returns:
        None: Print search results.

    """
    arg_count = 0
    col_width = 0

    for results_sorted in results_arg:
        if results_sorted:
            max_query = max(results_sorted, key=lambda item: item[1])
            col_width_temp = len(str(max_query[1]))
            if col_width_temp > col_width:
                col_width = col_width_temp

    print(f"{search} total queries: {count}")
    print("results:")

    for results_sorted in results_arg:
        arg_count += 1
        if results_sorted:
            try:
                for domain_name, query_count in results_sorted:
                    print(f"{query_count:>{col_width}}    {domain_name}")
            except BrokenPipeError:
                sys.exit(1)
        else:
            print("No results found.")
        if arg_count < len(results_arg):
            print("")


def menu():
    """Print main menu."""
    print("\ndnscl Menu:\n")
    # print_figlet("dnscl", font="ogre", colors="BLUE")
    print("Enter 0 to exit")
    print("Enter 1 to search ip")
    print("Enter 2 to search domain")
    print("Enter 3 to search rpz ip")
    print("Enter 4 to search rpz domain")
    print("Enter 5 to search ip by record type")
    print("Enter 6 to search domain by record type")
    print("Enter 7 to search record type details")


def main():
    """Run main program."""
    if len(sys.argv) < 2:
        filename = input("Enter syslog file (ENTER for default): ")
        if filename:
            check_file = pathlib.Path(filename)
            is_valid_file = check_file.is_file()
            while not is_valid_file:
                filename = input("Invalid file or directory, try again: ")
                if not filename:
                    filename = FILENAME
                    check_file = pathlib.Path(filename)
                    is_valid_file = check_file.is_file()
                else:
                    check_file = pathlib.Path(filename)
                    is_valid_file = check_file.is_file()
        else:
            filename = FILENAME
        print(f"Syslog file to search: {filename}")
        while True:
            menu()
            choice = input("=> ")
            while not choice.isdigit():
                print("Invalid input, try again.")
                menu()
                choice = input("=> ")
            if int(choice) == 1:
                ip_addr = input("ip address: ")
                dnscl_ipaddress(ip_addr, filename)
            elif int(choice) == 2:
                domain = input("domain name: ")
                dnscl_domain(domain, filename)
            elif int(choice) == 3:
                ip_addr = input("rpz ip: ")
                dnscl_rpz(ip_addr, filename)
            elif int(choice) == 4:
                domain = input("rpz domain name: ")
                dnscl_rpz_domain(domain, filename)
            elif int(choice) == 5:
                ip_addr = input("ip address: ")
                dnscl_record_ip(ip_addr, filename)
            elif int(choice) == 6:
                domain = input("domain: ")
                dnscl_record_domain(domain, filename)
            elif int(choice) == 7:
                rec_type = input("record type: ")
                dnscl_record_type(rec_type, filename)
            elif int(choice) > 7:
                print("Invalid choice, try again.")
            elif int(choice) == 0:
                break
    else:
        wildcard = ""
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
        parser_ip.add_argument("-i", help="ip address", default=wildcard)
        parser_ip.add_argument("-f", help="syslog file", default=FILENAME)
        parser_ip.add_argument("-d", help="domain", default=wildcard)
        parser_ip.add_argument("-q", "--quiet", help="quiet mode", action="store_true")
        parser_domain.add_argument("-d", help="domain", default=wildcard)
        parser_domain.add_argument("-f", help="syslog file", default=FILENAME)
        parser_domain.add_argument("-i", help="ip address", default=wildcard)
        parser_domain.add_argument(
            "-q", "--quiet", help="quiet mode", action="store_true"
        )
        parser_rpz.add_argument("-r", help="rpz domain", default=wildcard)
        parser_rpz.add_argument("-f", help="syslog file", default=FILENAME)
        parser_type.add_argument("-t", help="record type", default=wildcard)
        parser_type.add_argument("-f", help="syslog file", default=FILENAME)
        dnscl_parser.add_argument(
            "-v",
            "--version",
            action="version",
            version="%(prog)s " + __version__ + ", " + __author__ + " (c) 2021",
        )
        args = dnscl_parser.parse_args()

        if args.command == "ip":
            dnscl_ipaddress(args.i, args.f, args.d, args.quiet)
        elif args.command == "domain":
            dnscl_domain(args.d, args.f, args.i, args.quiet)
        elif args.command == "rpz":
            if args.r == wildcard:
                dnscl_rpz(args.r, args.f)
            else:
                dnscl_rpz_domain(args.r, args.f)
        elif args.command == "type":
            if args.t == wildcard:
                dnscl_record_domain(args.t, args.f)
            else:
                dnscl_record_type(args.t, args.f)


if __name__ == "__main__":
    main()
