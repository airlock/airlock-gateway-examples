#!/usr/bin/env python3
# coding=utf-8

from urllib import request
import ssl
import json
import os
import sys
import re
from argparse import ArgumentParser
from http.cookiejar import CookieJar

###############################################################################
# Version 1.0

# Example usage
# ./ip_list.py -a -n airlock.ergon.ch -l ^mapping_a$ -i ^IP-list99$ -b

API_KEY_FILE = "./api_key"
###############################################################################

parser = ArgumentParser()
parser.add_argument("-n", dest="host", metavar="hostname", required=True,
                    help="Airlock Gateway hostname")
group_action = parser.add_mutually_exclusive_group(required=True)
group_action.add_argument("-a", dest="action", action="store_const",
                          const="add", help="Add IP list")
group_action.add_argument("-r", dest="action", action="store_const",
                          const="remove", help="Remove IP list")
group_sel = parser.add_mutually_exclusive_group(required=True)
group_sel.add_argument("-m", dest="mapping_selector_pattern",
                       metavar="pattern", help="Pattern matching mapping name, e.g. ^mapping_a$")
group_sel.add_argument("-l", dest="mapping_selector_label", metavar="label",
                       help="Label for mapping selection")
parser.add_argument("-i", dest="iplist", metavar="pattern", required=True,
                    help="Pattern matching IP list, e.g. ^IP-list99$")
group_type = parser.add_mutually_exclusive_group(required=True)
group_type.add_argument("-w", dest="blacklist", action="store_false",
                        help="Modify whitelist")
group_type.add_argument("-b", dest="blacklist", action="store_true",
                        help="Modify blacklist")
parser.add_argument("-f", dest="confirm", action="store_false",
                    help="Force, no confirmation needed")

args = parser.parse_args()
sys.tracebacklimit = 0

TARGET_GATEWAY = "https://{}".format(args.host)

try:
    api_key = open(API_KEY_FILE, 'r').read().strip()
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


# create session
send_request("POST", "session/create")

# get last config (active or saved)
resp = json.loads(send_request("GET", "configuration/configurations"))
send_request("POST", "configuration/configurations/{}/load".format(resp['data'][0]['id']))

# get all mappings
resp = json.loads(send_request("GET", "configuration/mappings"))

# filter mappings
mapping_ids = (
    [x['id'] for x in resp['data']
        if(re.search(args.mapping_selector_pattern, x['attributes']['name']))]
    if args.mapping_selector_pattern
    else [x['id'] for x in resp['data']
          if(args.mapping_selector_label in x['attributes']['labels'])])
mapping_names = [x['attributes']['name'] for x in resp['data']
                 if(x['id'] in mapping_ids)]

if not mapping_ids:
    sys.exit("No mapping found - exit")

# get all ip lists
resp = json.loads(send_request("GET", "configuration/ip-address-lists"))

# filter ip lists
ip_list_ids = [x['id'] for x in resp['data']
               if(re.search(args.iplist, x['attributes']['name']))]
ip_list_names = [x['attributes']['name'] for x in resp['data']
                 if(x['id'] in ip_list_ids)]

if not ip_list_ids:
    sys.exit("IP list matching '{}' not found".format(args.iplist))
else:
    ip_list_id = ip_list_ids[0]

# patch the config
for mapping_id in mapping_ids:
    resp = json.loads(send_request("GET", "/configuration/mappings/{}"
                                          .format(mapping_id)))
    list_type = "blacklists" if args.blacklist else "whitelists"

    selected_ip_list = []
    for ip_list_id in ip_list_ids:
        selected_ip_list.append({"id": ip_list_id, "type": "ip-address-list"})

    data = {"data": selected_ip_list}
    method = "PATCH" if args.action == "add" else "DELETE"
    send_request(method,
                 "configuration/mappings/{}/relationships/ip-address-{}"
                 .format(mapping_id, list_type), json.dumps(data))

if args.confirm:
    answer = input('{} {} group(s) "{}" - mapping(s): {}\nContinue to save the config? [y/n] '
                   .format(args.action, list_type[:-1],
                           ', '.join(ip_list_names), '\n\t'
                           .join(sorted(mapping_names))))
    answer != 'y' and sys.exit("Nothing changed")

config_comment = 'REST: {} {} IP list(s) "{}" on mapping(s): "{}"' \
    .format(args.action, list_type[:-1],
            ', '.join(ip_list_names), ', '.join(sorted(mapping_names)))
data = {"comment": config_comment}

# save config
send_request("POST", "configuration/configurations/save", json.dumps(data))
print('Config saved with comment: {}'.format(config_comment))

# activate config without failover activation!
# send_request("POST", "configuration/configurations/activate",
#              json.dumps(data))

# logout
send_request("POST", "session/terminate")
