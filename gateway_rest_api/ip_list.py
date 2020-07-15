#!/usr/bin/env python3
# coding=utf-8
"""
Version 1.2
Script to manage IP list usages
All actions operate on the newest saved or active configuration.
"""

from urllib import request
import ssl
import json
import os
import sys
import re
from argparse import ArgumentParser
from http.cookiejar import CookieJar
import signal
import itertools

API_KEY_FILE = "./api_key"

parser = ArgumentParser()
parser.add_argument("-n", dest="host", metavar="hostname",
                    required=True,
                    help="Airlock Gateway hostname")
group_action = parser.add_mutually_exclusive_group(required=True)
group_action.add_argument("-a", dest="action", action="store_const",
                          const="add", help="Add IP list")
group_action.add_argument("-r", dest="action", action="store_const",
                          const="remove", help="Remove IP list")
group_action.add_argument("-s", dest="action", action="store_const",
                          const="show", help="Show IP list usage")
group_sel = parser.add_mutually_exclusive_group(required=True)
group_sel.add_argument("-m", dest="mapping_selector_pattern",
                       metavar="pattern",
                       help="Pattern matching mapping name, e.g. ^mapping_a$")
group_sel.add_argument("-l", dest="mapping_selector_label", metavar="label",
                       help="Label for mapping selection")
parser.add_argument("-i", dest="iplist", metavar="pattern",
                    help="Pattern matching IP list, e.g. ^IP-list99$")
group_type = parser.add_mutually_exclusive_group(required=True)
group_type.add_argument("-w", dest="blacklist", action="store_false",
                        help="Modify whitelist")
group_type.add_argument("-b", dest="blacklist", action="store_true",
                        help="Modify blacklist")
parser.add_argument("-o", dest="log_only",
                    choices=['true', 'false'],
                    help="Enable/disable 'log only' on all affected mappings "
                    "for the specified IP list type")
parser.add_argument("-f", dest="confirm", action="store_false",
                    help="Force, no confirmation needed")
parser.add_argument("-k", dest="api_key", metavar="api_key",
                    help=f"API key if not specified in {API_KEY_FILE}")
args = parser.parse_args()
sys.tracebacklimit = 0

if args.log_only and args.iplist is None:
    parser.error("-i or -o (or both) required")

TARGET_GATEWAY = f'https://{args.host}'

try:
    api_key = (args.api_key if args.api_key
               else open(API_KEY_FILE, 'r').read().strip())
except IOError:
    print(f'Please write the Airlock Gateway API key into file {API_KEY_FILE}')
    sys.exit(-1)

DEFAULT_HEADERS = {"Accept": "application/json",
                   "Content-Type": "application/json",
                   "Authorization": f'Bearer {api_key}'}

# we need a cookie store
opener = request.build_opener(request.HTTPCookieProcessor(CookieJar()))

# ignore invalid SSL cert on the management interface
if (not os.environ.get('PYTHONHTTPSVERIFY', '') and
        getattr(ssl, '_create_unverified_context', None)):
    ssl._create_default_https_context = ssl._create_unverified_context


# method to send REST calls
def send_request(method, path, body=""):
    req = request.Request(TARGET_GATEWAY + "/airlock/rest/" + path,
                          body.encode('utf-8'), DEFAULT_HEADERS)
    req.get_method = lambda: method
    r = opener.open(req)
    return r.read()


def terminate_and_exit(text):
    send_request("POST", "session/terminate")
    sys.exit(text)


# signal handler
def register_cleanup_handler():
    def cleanup(signum, frame):
        terminate_and_exit("Terminate session")

    for sig in (signal.SIGABRT, signal.SIGILL, signal.SIGINT, signal.SIGSEGV,
                signal.SIGTERM):
        signal.signal(sig, cleanup)


def load_last_config():
    resp = json.loads(send_request("GET", "configuration/configurations"))
    send_request("POST", 'configuration/configurations/'
                         f"{resp['data'][0]['id']}/load")


def get_all_mappings():
    resp = json.loads(send_request("GET", "configuration/mappings"))['data']
    return sorted(resp, key = lambda x: x['attributes']['name'])


def get_mappings():
    # filter mappings
    return ([
        {'id': x['id'],
         'name': x['attributes']['name'],
         'ip_rules': x['attributes']['ipRules']}
        for x in get_all_mappings() if (
            args.mapping_selector_pattern and
            re.search(args.mapping_selector_pattern, x['attributes']['name']) or
            args.mapping_selector_label in x['attributes']['labels']
            )
        ])


def get_all_ip_lists():
    # get all ip lists
    resp = json.loads(send_request("GET", "configuration/ip-address-lists"))
    return resp['data']


def get_ip_lists():
    ip_lists = []
    if args.iplist:
        ip_lists = ([
            {'id': x['id'], 'name': x['attributes']['name']}
            for x in get_all_ip_lists() if (
                re.search(args.iplist, x['attributes']['name'])
            )
        ])
    return ip_lists


def show_usages(mappings, list_type):
    dump = {}
    for mapping in mappings:
        dump[mapping['id']] = {
            'name': mapping['name'],
            'log_only': mapping['ip_rules'][f'ipAddress{list_type.title()}']['logOnly'],
            'ip_lists': []
            }

    for r in json.loads(send_request("GET", "/configuration/ip-address-lists"))['data']:
        key_name = f'ip-address-{list_type}'
        if 'relationships' in r and key_name in r['relationships']:
            for m in r['relationships'][key_name]['data']:
                if m['id'] in dump:
                    dump[m['id']]['ip_lists'].append(r['id'])

    all_ip_lists = get_all_ip_lists()
    for mapping_infos in dump.values():
        print(mapping_infos['name'])
        print(f"\tlog-only: {mapping_infos['log_only']}")
        print('\tIP {}: {}'.format(list_type, ', '.join(
            i['attributes']['name'] for i in all_ip_lists if
            i['id'] in mapping_infos['ip_lists'])))


def patch_config(mappings, list_type, ip_lists):
    for mapping in mappings:
        selected_ip_list = []
        for ip_list in ip_lists:
            selected_ip_list.append({"id": ip_list['id'],
                                    "type": "ip-address-list"})

        data = {"data": selected_ip_list}
        method = "PATCH" if args.action == "add" else "DELETE"
        send_request(method,
                    "configuration/mappings/{}/relationships/ip-address-{}"
                    .format(mapping['id'], list_type), json.dumps(data))
        if args.log_only:
            data = {
                "data": {
                    "attributes": {
                        "ipRules": {
                            f"ipAddress{list_type.title()}": {
                                "logOnly": True if args.log_only == "true"
                                else False
                            }
                        }
                    },
                    "id": mapping['id'],
                    "type": "mapping"
                }
            }
            send_request("PATCH", f"configuration/mappings/{mapping['id']}",
                         json.dumps(data))


def create_change_info(mappings, list_type, ip_lists):
    change_info = ''
    if args.iplist:
        change_info += '{} {} group(s) "{}"'\
                       .format(args.action,
                               list_type[:-1],
                               ', '.join(x['name'] for x in ip_lists))
        if args.log_only: change_info += ' and '
    if args.log_only:
        change_info += f'set log_only to "{args.log_only}"'
    change_info += ' for the following mapping(s): \n\t{}'\
                   .format('\n\t'.join(sorted(x['name'] for x in mappings)))
    return change_info


def confirm(change_info):
    if not args.confirm:
        return True
    print(change_info)
    if input('\nContinue to save the config? [y/n] ') == 'y':
        return True
    print("Nothing changed")
    return False


def save_config(change_info):
    data = {"comment": "REST: " + change_info.replace('\n\t', ', ').replace(': ,', ':')}

    # save config
    send_request("POST", "configuration/configurations/save", json.dumps(data))
    print(f"Config saved with comment: {data['comment']}")


# create session
send_request("POST", "session/create")
register_cleanup_handler()

# load last config (active or saved)
load_last_config()

# filter mappings
mappings = get_mappings()
if not mappings: terminate_and_exit("No mapping found - exit")

# filter ip lists
ip_lists = get_ip_lists()
if args.action != "show" and not ip_lists:
    terminate_and_exit("No IP list found")

list_type = "blacklists" if args.blacklist else "whitelists"

if args.action == "show":
    show_usages(mappings, list_type)
else:
    patch_config(mappings, list_type, ip_lists)
    change_info = create_change_info(mappings, list_type, ip_lists)
    confirm(change_info) or terminate_and_exit(0)
    save_config(change_info)

terminate_and_exit(0)
