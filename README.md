# Dnscl

[![Build Status](https://travis-ci.com/mark-w-hunter/dnscl.svg?branch=master)](https://travis-ci.com/mark-w-hunter/dnscl)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
 
This program analyzes BIND DNS query data from syslog file input

## functions

dnscl_domain(domain)
    Returns a list of client IP addresses that queried a domain name

dnscl_ipaddress(ip)
    Returns a list of domain names queried by a client IP address

dnscl_rpz(ip_address)
    Returns rpz names queried by a client IP address

dnscl_rpz_domain(domain_rpz_name)
    Returns cllent IP addresses that queried a rpz domain name

menu()
    Prints main menu

## usage

Step 1: Set path and filename to local syslog file.

Step 2: Set field number for domain name.

Step 3: Set field number for IP address.

Step 4: Run dnscl.py using text menu interface:
```
./dnscl.py
```
```
python3 dnscl.py
```
Step 5: Run dnscl.py directly using command-line arguments.

### Examples:

Search for all domain names queried by 10.0.0.45
```
./dnscl.py ip 10.0.0.45
```
Search for all IP addresses that queried www.foo.org
```
./dnscl.py domain www.foo.org
```
Return a list of all domain names queried by any IP address
```
./dnscl.py ip --all
```
Return a list of all IP addresses that queried any domain name
```
./dnscl.py domain --all
```
Search for all rpz names queried
```
./dnscl.py rpz --all
