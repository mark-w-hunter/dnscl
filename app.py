#!/usr/bin/env python3

# Flask app for dnscl
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

"""Flask app to analyze BIND DNS queries from syslog input."""

from flask import Flask, request
import dnscl_api as dnscl
app = Flask(__name__)


def get_input():
    search = request.args.get("search")
    return search


def get_ip_input():
    ip = request.args.get("ip")
    return ip


def get_domain_input():
    domain = request.args.get("domain")
    return domain


@app.after_request
def convert_to_text(results):
    results.headers["content-type"] = "text/plain"
    return results


@app.route("/")
def dnscl_home_page():
    help_str = ""
    help_str += "dnscl - Analyze BIND DNS query data from syslog file input\n"
    help_str += "\nendpoints:\n"
    help_str += "/ip?search=ip&domain=domain\n"
    help_str += "/domain?search=domain&ip=ip\n"
    help_str += "/rpz?search=domain\n"
    help_str += "/type?search=type\n"
    help_str += "\nusage examples:\n"
    help_str += "return all domains queried by any ip address\n"
    help_str += "http://127.0.0.1:5000/ip\n"
    help_str += "\nreturn all domains queried by 192.168.0.1\n"
    help_str += "http://127.0.0.1:5000/ip?search=192.168.0.1\n"
    help_str += "\nreturn domains containing 'google' queried any ip address\n"
    help_str += "http://127.0.0.1:5000/ip?domain=google\n"
    help_str += "\nreturn domains containing 'amazon' queried by 192.168.0.1\n"
    help_str += "http://127.0.0.1:5000/ip?search=192.168.0.1&domain=amazon\n"
    return help_str


@app.route("/ip")
def dnscl_ip_page():
    wildcard = ""
    search = get_input()
    domain = get_domain_input()
    if search:
        if domain:
            results = dnscl.dnscl_ipaddress(search, domain)
        else:
            results = dnscl.dnscl_ipaddress(search)
    elif domain:
        results = dnscl.dnscl_ipaddress(wildcard, domain)
    else:
        results = dnscl.dnscl_ipaddress(wildcard)
    return results


@app.route("/domain")
def dnscl_domain_page():
    wildcard = ""
    search = get_input()
    ip = get_ip_input()
    if search:
        if ip:
            results = dnscl.dnscl_domain(search, ip)
        else:
            results = dnscl.dnscl_domain(search)
    elif ip:
        results = dnscl.dnscl_domain(wildcard, ip)
    else:
        results = dnscl.dnscl_domain(wildcard)
    return results


@app.route("/rpz")
def dnscl_rpz_page():
    wildcard = ""
    search = get_input()
    if search:
        results = dnscl.dnscl_rpz_domain(search)
    else:
        results = dnscl.dnscl_rpz(wildcard)
    return results


@app.route("/type")
def dnscl_type_page():
    wildcard = ""
    search = get_input()
    if search:
        results = dnscl.dnscl_record_type(search)
    else:
        results = dnscl.dnscl_record_domain(wildcard)
    return results


if __name__ == "__main__":
    app.run(port="5000", debug=True)
