#!/usr/bin/env python3

# dnscl: Analyze BIND DNS query data from syslog file input
# version: 0.32
# https://github.com/mark-w-hunter/dnscl
#
# The MIT License (MIT)
#
# Copyright (c) 2019 Mark W. Hunter
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

""" This program analyzes DNS queries from syslog input """
import sys
from itertools import groupby
import timeit

FILENAME = "/var/log/messages"  # path to syslog file


def dnscl_ipaddress(ip_address):
    """ Returns domain names queried by a client IP address """
    start_time = timeit.default_timer()
    my_list = []
    line_count = 0
    ip_address_search = ip_address + "#"
    for line in open(FILENAME):
        if ip_address_search in line:
            if "query:" in line:
                fields = (line.strip().split(" "))
                if len(fields) > 12:
                    my_list.append(fields[8])  # field containing domain name
                    line_count = line_count + 1

    my_set = sorted(set(my_list))
    my_list_final = [(len(list(dcount)), dname) for dname, dcount in groupby(sorted(my_list))]
    my_list_final.sort(reverse=True)
    elapsed_time = timeit.default_timer() - start_time

    print(ip_address, "total queries are", line_count)
    print("queries: ")

    for query_count, domain_name in my_list_final:
        print(query_count, "\t", domain_name)

    print("\nSummary: Searched", ip_address, "and found", line_count,
          "queries for", len(my_set), "domain names.")
    print("Query time:", str(round(elapsed_time, 2)), "seconds")


def dnscl_domain(domain_name):
    """ Returns cllent IP addresses that queried a domain name """
    start_time = timeit.default_timer()
    my_list = []
    my_domain_list = []
    line_count = 0

    for line in open(FILENAME):
        if domain_name in line:
            if "query:" in line:
                fields = (line.strip().split(" "))
                if domain_name in fields[8] and len(fields) > 12: # field containing domain name
                    ip_address = fields[5].split("#")  # field containing ip
                    my_list.append(ip_address[0])
                    if domain_name != "":
                        my_domain_list.append(fields[8]) # field containing domain name
                    line_count = line_count + 1

    my_set = sorted(set(my_list))
    my_domain_set = sorted(set(my_domain_list))
    my_list_final = [(len(list(dcount)), dname) for dname, dcount in groupby(sorted(my_list))]
    my_list_final.sort(reverse=True)
    elapsed_time = timeit.default_timer() - start_time

    print(domain_name, "total queries are", line_count)
    print("ip addresses: ")

    for query_count, ip_address in my_list_final:
        print(query_count, "\t", ip_address)

    if domain_name != "":
        print("\ndomain names: ")

        for domain_names_found in my_domain_set:
            print(domain_names_found)

    print("\nSummary: Searched", domain_name, "and found", line_count,
          "queries from", len(my_set), "clients.")
    print("Query time:", str(round(elapsed_time, 2)), "seconds")


def dnscl_rpz(ip_address):
    """ Returns rpz names queried by a client IP address """
    start_time = timeit.default_timer()
    my_list = []
    line_count = 0
    ip_address_search = ip_address + "#"
    for line in open(FILENAME):
        if ip_address_search in line:
            if "rpz" in line and "SOA" not in line:
                fields = (line.strip().split(" "))
                if len(fields) > 11:
                    my_list.append(fields[11])  # field containing rpz domain name
                    line_count = line_count + 1

    my_set = sorted(set(my_list))
    my_list_final = [(len(list(dcount)), dname) for dname, dcount in groupby(sorted(my_list))]
    my_list_final.sort(reverse=True)
    elapsed_time = timeit.default_timer() - start_time

    print(ip_address, "total queries are", line_count)
    print("queries: ")

    for query_count, domain_name in my_list_final:
        print(query_count, "\t", domain_name)

    print("\nSummary: Searched", ip_address, "and found", line_count,
          "queries for", len(my_set), "rpz names.")
    print("Query time:", str(round(elapsed_time, 2)), "seconds")

def dnscl_rpz_domain(domain_rpz_name):
    """ Returns cllent IP addresses that queried a rpz domain name """
    start_time = timeit.default_timer()
    my_list = []
    my_domain_list = []
    line_count = 0

    for line in open(FILENAME):
        if domain_rpz_name in line:
            if "rpz" in line and "SOA" not in line:
                fields = (line.strip().split(" "))
                if domain_rpz_name in fields[11] and len(fields) > 11:
                    ip_address = fields[5].split("#")  # field containing ip
                    my_list.append(ip_address[0])
                    if domain_rpz_name != "":
                        my_domain_list.append(fields[11]) # field containing rpz domain name
                    line_count = line_count + 1

    my_set = sorted(set(my_list))
    my_domain_set = sorted(set(my_domain_list))
    my_list_final = [(len(list(dcount)), dname) for dname, dcount in groupby(sorted(my_list))]
    my_list_final.sort(reverse=True)
    elapsed_time = timeit.default_timer() - start_time

    print(domain_rpz_name, "total queries are", line_count)
    print("ip addresses: ")

    for query_count, ip_address in my_list_final:
        print(query_count, "\t", ip_address)

    if domain_rpz_name != "":
        print("\nrpz names: ")

        for domain_names_found in my_domain_set:
            print(domain_names_found)

    print("\nSummary: Searched", domain_rpz_name, "and found", line_count,
          "queries from", len(my_set), "clients.")
    print("Query time:", str(round(elapsed_time, 2)), "seconds")


def menu():
    """ Prints main menu """
    print("\nDnscl Main Menu:\n")
    print("Enter 0 to exit")
    print("Enter 1 to search ip address")
    print("Enter 2 to search domain name")
    print("Enter 3 to search rpz ip address")
    print("Enter 4 to search rpz domain name")

if __name__ == "__main__":
    if len(sys.argv) < 3:
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
            elif int(CHOICE) == 3:
                IP = input("rpz ip: ")
                dnscl_rpz(IP)
            elif int(CHOICE) == 4:
                DOMAIN = input("rpz domain name: ")
                dnscl_rpz_domain(DOMAIN)
            elif int(CHOICE) > 4:
                print("Invalid choice, try again.")
    elif sys.argv[1] == "ip" and len(sys.argv) == 3:
        if sys.argv[2] == "--all":
            WILDCARD = ""
            dnscl_ipaddress(WILDCARD)
        else:
            dnscl_ipaddress(sys.argv[2])
    elif sys.argv[1] == "domain" and len(sys.argv) == 3:
        if sys.argv[2] == "--all":
            WILDCARD = ""
            dnscl_domain(WILDCARD)
        else:
            dnscl_domain(sys.argv[2])
    elif sys.argv[1] == "rpz" and len(sys.argv) == 3:
        if sys.argv[2] == "--all":
            WILDCARD = ""
            dnscl_rpz(WILDCARD)
        else:
            dnscl_rpz_domain(sys.argv[2])
    else:
        print("Error, try again.")
