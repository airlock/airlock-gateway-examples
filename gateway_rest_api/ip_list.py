#!/usr/bin/env python3
# coding=utf-8
"""
Version 1.1
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

TARGET_GATEWAY = "https://{}".format(args.host)

try:
    api_key = (args.api_key if args.api_key
               else open(API_KEY_FILE, 'r').read().strip())
except IOError:
    print("Please write the Airlock Gateway API key into file {}"
          .format(API_KEY_FILE))
    sys.exit(-1)

DEFAULT_HEADERS = {"Accept": "application/json",
                   "Content-Type": "application/json",
                   "Authorization": "Bearer {}".format(api_key)}

# we need a cookie store
opener = request.build_opener(request.HTTPCookieProcessor(CookieJar()))

# for invalid SSL certs on the management interface
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
    send_request("POST", "configuration/configurations/{}/load"
                         .format(resp['data'][0]['id']))


def get_all_mappings():
    return json.loads(send_request("GET", "configuration/mappings"))


def filter_mappings(all_mappings):
    # filter mappings
    return ([
        {'id': x['id'], 'name': x['attributes']['name']}
        for x in all_mappings['data'] if (
            args.mapping_selector_pattern and
            re.search(args.mapping_selector_pattern, x['attributes']['name']) or
            args.mapping_selector_label in x['attributes']['labels']
            )
        ])


def get_ip_lists():
    # get all ip lists
    resp = json.loads(send_request("GET", "configuration/ip-address-lists"))

    ip_lists = []
    if args.iplist:
        ip_lists = ([
            {'id': x['id'], 'name': x['attributes']['name']}
            for x in resp['data'] if (
                re.search(args.iplist, x['attributes']['name'])
            )
        ])
    return ip_lists


def show_usages(all_mappings, mappings, list_type, ip_lists):
    dump = {}
    for mapping in all_mappings['data']:
        ipr = mapping['attributes']['ipRules']
        dump[mapping['id']] = {
            'ip_lists': [],
            'log_only': ipr['ipAddress{}'.format(list_type.title())]['logOnly']
            }

    resp = json.loads(send_request("GET", "/configuration/ip-address-lists"))
    for r in resp['data']:
        for m in r['relationships'][f'ip-address-{list_type}']['data']:
            if m['id'] in dump:
                dump[m['id']]['ip_lists'].append(r['id'])

    for mapping_id, mapping_ip_list in list(dump.items()):
        print('{}'.format(list(m['name'] for m in mappings
                        if m['id'] == mapping_id)[0]))
        print('\tlog-only: {}'.format(mapping_ip_list['log_only']))
        print('\tIP {}: {}'.format(list_type, ', '.join(
            list(ipl['name'] for ipl in ip_lists if ipl['id'] == mipl)[0]
            for mipl in mapping_ip_list['ip_lists'])))

    terminate_and_exit(0)


def patch_config(mappings, list_type, ip_lists):
    for mapping in mappings:
        resp = json.loads(send_request("GET", "/configuration/mappings/{}"
                                              .format(mapping['id'])))

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
                        "ipAddress{}".format(list_type.title()): {
                            "logOnly": True if args.log_only == "true"
                            else False
                        }
                    }
                },
                "id": mapping_id,
                "type": "mapping"
            }
        }
        send_request("PATCH", "configuration/mappings/{}"
                     .format(mapping_id), json.dumps(data))


def create_change_info(mappings, list_type, ip_lists):
    change_info = ''
    if args.iplist:
        change_info += '{} {} group(s) "{}"'\
                       .format(args.action, list_type[:-1],
                               ', '.join(x['name'] for x in ip_lists))
        if args.log_only:
            change_info += ' and '
    if args.log_only:
        change_info += 'set log_only to "{}"'.format(args.log_only)
    change_info += ' for the following mapping(s): \n\t{}'\
                   .format('\n\t'.join(sorted(x['name'] for x in mappings)))
    return change_info


def confirm(change_info):
    if args.confirm:
        print(change_info)
        if input('\nContinue to save the config? [y/n] ') == 'y':
            return True
        else:
            print("Nothing changed")
            return False


def save_config(change_info):
    data = {"comment": "REST: " + change_info.replace('\n', '').replace('\t', ',')}

    # save config
    send_request("POST", "configuration/configurations/save", json.dumps(data))
    print('Config saved with comment: {}'.format(data['comment']))


def activate_config():
    nop
    # activate config without failover activation!
    # send_request("POST", "configuration/configurations/activate",
    #              json.dumps(data))


def main():
    # create session
    send_request("POST", "session/create")
    register_cleanup_handler()

    # load last config (active or saved)
    load_last_config()

    all_mappings = get_all_mappings()
    # filter mappings
    mappings = filter_mappings(all_mappings)
    if not mappings:
        terminate_and_exit("No mapping found - exit")

    # filter ip lists
    ip_lists = get_ip_lists()
    if not ip_lists:
        terminate_and_exit("IP list matching '{}' not found"
                           .format(args.iplist))

    list_type = "blacklists" if args.blacklist else "whitelists"

    # show ip list usage and terminate
    if args.action == "show":
        show_usages(all_mappings, mappings, list_type, ip_lists)

    patch_config(mappings, list_type, ip_lists)
    change_info = create_change_info(mappings, list_type, ip_lists)
    confirm(change_info) or terminate_and_exit(0)
    save_config(change_info)
    terminate_and_exit(0)


if __name__ == '__main__':
    main()
