#!/usr/bin/env python3
# coding=utf-8
"""
version 3.0
Script to:
    - show mappings with activated maintenance page
        ./maintenance.py -h my_airlock -m "^mapping.*pattern$" -a show
    - activate/deactivate maintenance on a mapping
        ./maintenance.py -h my_airlock -m "^mapping.*pattern$" -a enable
    - delete WAF mappings
        ./maintenance.py -h my_airlock -m "^mapping.*pattern$" -a delete

- Tested with Airlock Gateway 7.8
- Operates on the last saved/activated config
- Activates new config, requires confirmation by default
"""

from urllib import request
import requests
import ssl
import json
import os
import sys
import re
from argparse import ArgumentParser
from http.cookiejar import CookieJar
import signal

# file to store REST API key (Configcenter - System Setup - System Admin)
API_KEY_FILE = "./api_key"

parser = ArgumentParser(add_help=False)
parser.add_argument("-h", dest="host", metavar="<WAF hostname>",
                    required=True, help="Airlock WAF hostname")
parser.add_argument("-m", dest="mapping_selector_pattern",
                    required=True, metavar="pattern",
                    help="Pattern matching mapping name(s), e.g. ^mapping_a$")
parser.add_argument("-a", choices=['enable', 'disable', 'show', 'delete'], dest="action",
                    required=True, help="Enable or disable maintenance page")
parser.add_argument("-f", dest="confirm", action="store_false",
                    help="Force, no confirmation needed")

args = parser.parse_args()

try:
    api_key = open(API_KEY_FILE, 'r').read().strip()
except OSError:
    print(f'There was an error opening the file {API_KEY_FILE}')
    sys.exit(1)

DEFAULT_HEADERS = {"Authorization": f'Bearer {api_key}'}

opener = request.build_opener(request.HTTPCookieProcessor(CookieJar()))
# ignore invalid SSL cert on the management interface
if (not os.environ.get('PYTHONHTTPSVERIFY', '') and
        getattr(ssl, '_create_unverified_context', None)):
    ssl._create_default_https_context = ssl._create_unverified_context


def send_request(
        method,
        path,
        body="",
        accept_header="application/json",
        content_type="application/json"):
    DEFAULT_HEADERS['Accept'] = accept_header
    DEFAULT_HEADERS['Content-Type'] = content_type
    if content_type == "application/json":
        body = body.encode('utf-8')
    req = request.Request(f'https://{args.host}/airlock/rest/' + path,
                          body, DEFAULT_HEADERS)
    req.get_method = lambda: method
    r = opener.open(req)
    return r.read()


def terminate_and_exit(text):
    send_request("POST", "session/terminate")
    sys.exit(text)


def register_cleanup_handler():
    def cleanup(signum, frame):
        terminate_and_exit("Terminate session")

    for sig in (signal.SIGABRT, signal.SIGILL, signal.SIGINT, signal.SIGSEGV,
                signal.SIGTERM):
        signal.signal(sig, cleanup)


def get_mappings():
    def get_all_mappings():
        resp = json.loads(send_request(
            "GET", "configuration/mappings"))['data']
        return sorted(resp, key=lambda x: x['attributes']['name'])

    return ([
        {'id': x['id'],
         'name': x['attributes']['name'],
         'maintenance_page': x['attributes']['enableMaintenancePage']}
        for x in get_all_mappings() if (
            re.search(args.mapping_selector_pattern,
                      x['attributes']['name'])
        )
    ])


def create_change_info(affected_mapping_names):
    change_info = ''
    if args.action == "enable":
        change_info += "Enable maintenance page for"
    elif args.action == "disable":
        change_info += "Disable maintenance page for"
    elif args.action == "delete":
        change_info += "Delete"

    change_info += ' the following mapping(s): \n\t{}'\
                   .format('\n\t'.join(affected_mapping_names))
    return change_info


def confirm(change_info):
    if not args.confirm:
        return True
    print(change_info)
    if input('\nContinue to activate the new config? [y/n] ') == 'y':
        return True
    print("Nothing changed")
    return False


def activate_config(change_info):
    confirm(change_info) or terminate_and_exit(0)

    data = {"comment": "REST: " +
            change_info.replace('\n\t', ', ').replace(': ,', ':')}
    send_request("POST", "configuration/configurations/activate",
                 json.dumps(data))


send_request("POST", "session/create")
register_cleanup_handler()

resp = json.loads(send_request("GET", "configuration/configurations"))
send_request("POST", 'configuration/configurations/'
             f"{resp['data'][0]['id']}/load")

mappings = get_mappings() or terminate_and_exit("No mapping found - exit")

if args.action == "show":
    print("Mapping Name, Maintenance Page Status")
    for mapping in mappings:
        print(f"{mapping['name']}, {mapping['maintenance_page']}")
else:
    if args.action in ["enable", "disable"]:
        for mapping in mappings:
            data = {
                "data": {
                    "attributes": {
                        "enableMaintenancePage": "true" if args.action == "enable" else "false"
                    },
                    "id": mapping['id'],
                    "type": "mapping"
                }
            }
            send_request(
                "PATCH", f"configuration/mappings/{mapping['id']}", json.dumps(data))
    elif args.action == "delete":
        for mapping in mappings:
            send_request("DELETE", f"configuration/mappings/{mapping['id']}")

    change_info = create_change_info(sorted(x['name'] for x in mappings))
    activate_config(change_info)

terminate_and_exit(0)
