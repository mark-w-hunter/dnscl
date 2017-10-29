#!/usr/bin/env python3
# Copyright (c) 2017 Mark W. Hunter <marcus.w.hunter@gmail.com>

""" This program analyzes DNS queries from syslog input """
from itertools import groupby

FILENAME = "/var/log/messages"  # path to syslog file


def dnscl_ipaddress(ip_address):
    """ Returns domain names queried by a client IP address """

    my_list = []
    line_count = 0
    ip_address_search = ip_address + "#"
    for line in open(FILENAME):
        if ip_address_search in line:
            if "query:" in line:
                fields = (line.strip().split(" "))
                if len(fields) > 12:
                    my_list.append(fields[9])  # field containing domain name
                    line_count = line_count + 1

    my_set = sorted(set(my_list))
    my_dict = dict([(dname, len(list(dcount))) for dname, dcount in
                    groupby(sorted(my_list))])
    my_dict_view = [(value, key) for key, value in my_dict.items()]
    my_dict_view.sort(reverse=True)

    print(ip_address, "total queries are", line_count)
    print("queries: ")

    for query_count, domain_name in my_dict_view:
        print(query_count, "\t", domain_name)

    print("\nSummary: Searched", ip_address, "and found", line_count,
          "queries for", len(my_set), "domain names.")


def dnscl_domain(domain_name):
    """ Returns cllent IP addresses that queried a domain name """
    my_list = []
    line_count = 0

    for line in open(FILENAME):
        if domain_name in line:
            if "query:" in line:
                fields = (line.strip().split(" "))
                if len(fields) > 12:
                    ip_address = fields[6].split("#")  # field containing ip
                    my_list.append(ip_address[0])
                    line_count = line_count + 1

    my_set = sorted(set(my_list))
    my_dict = dict([(a, len(list(b))) for a, b in groupby(sorted(my_list))])
    my_dict_view = [(v, k) for k, v in my_dict.items()]
    my_dict_view.sort(reverse=True)

    print(domain_name, "total queries are", line_count)
    print("addresses: ")

    for query_count, ip_address in my_dict_view:
        print(query_count, "\t", ip_address)

    print("\nSummary: Searched", domain_name, "and found", line_count,
          "queries from", len(my_set), "clients.")


def menu():
    """ Prints main menu """
    print("\n")
    print("Enter 0 to exit")
    print("Enter 1 to searh ip address")
    print("Enter 2 to search domain name")


while True:
    menu()
    CHOICE = input(">> ")
    try:
        int(CHOICE)
    except ValueError:
        print("Invalid input, exiting.")
        break

    if int(CHOICE) == 0:
        break
    elif int(CHOICE) == 1:
        IP = input("ip address: ")
        dnscl_ipaddress(IP)
    elif int(CHOICE) == 2:
        DOMAIN = input("domain name: ")
        dnscl_domain(DOMAIN)
    elif int(CHOICE) > 2:
        print("Invalid choice, try again")
