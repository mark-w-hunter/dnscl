# Dnscl

[![Build Status](https://travis-ci.com/mark-w-hunter/dnscl.svg?branch=devel)](https://travis-ci.com/mark-w-hunter/dnscl)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

This program analyzes BIND DNS query data from syslog file input

## usage

Step 1: Set path and filename to local Python 3 interpreter. Python 3.6 or higher required.

Step 2: Set path and filename to local syslog file.

Step 3: Run dnscl.py using text menu interface.

```bash
./dnscl.py
```

```bash
python3 dnscl.py
```

Step 4: Run dnscl.py directly using command-line arguments.

### Examples

Search for all domain names queried by 10.0.0.45

```bash
./dnscl.py ip 10.0.0.45
```

Search for all IP addresses that queried www.foo.org

```bash
./dnscl.py domain www.foo.org
```

Return a list of all domain names queried by any IP address

```bash
./dnscl.py ip --all
```

Return a list of all IP addresses that queried any domain name

```bash
./dnscl.py domain --all
```

Search for all rpz names queried

```bash
./dnscl.py rpz --all
```

Display help

```bash
./dnscl.py --help
```

## functions

dnscl_domain(domain)
    Returns a list of client IP addresses that queried a domain name

dnscl_ipaddress(ip)
    Returns a list of domain names queried by a client IP address

dnscl_rpz(ip_address)
    Returns rpz names queried by a client IP address

dnscl_rpz_domain(domain_rpz_name)
    Returns client IP addresses that queried a rpz domain name

dnscl_record_ip(ip_address)
    Returns record types queried by a client IP address

dnscl_record_domain(domain_name)
    Returns record types for a queried domain name

dnscl_record_type(record_type)
    Returns domain names of a particular record type

find_field(fields, field_index, field_type)
    Find and return requested field value

menu()
    Prints main menu
