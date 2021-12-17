#!/usr/bin/env python2
# coding=utf-8
"""
version 1.0
Adds JSON parameter name exception for Deny Rule TI_001d
"""

import urllib2
import ssl
import json
import os
import sys
from argparse import ArgumentParser
from cookielib import CookieJar
from signal import *

API_KEY_FILE = "./api_key"

parser = ArgumentParser(add_help=True)
parser.add_argument("-n", dest="host", metavar="<airlock host>",
                    required=True,
                    help="Airlock Gateway hostname")
group_action = parser.add_mutually_exclusive_group(required=True)
group_action.add_argument("-m", dest="mapping", metavar="<mapping name>",
                            help="Logical name of the mapping")
group_action.add_argument("-a", dest="allmappings", action='store_true',
                            help="activate exception on all mappings")

# TI_001d rule
deny_rule_group_id = -30028
deny_rule_id = -2202

args = parser.parse_args()

TARGET_WAF = "https://{}".format(args.host)
CONFIG_COMMENT = "Script: add JSON parameter name exception for Deny Rule TI_001d"

api_key = open(API_KEY_FILE, 'r').read().strip()
DEFAULT_HEADERS = {"Accept": "application/json",
                   "Content-Type": "application/json",
                   "Authorization": "Bearer {}".format(api_key)}


# we need a cookie store
cj = CookieJar()
opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj))

# if you have configured an invalid SSL cert on the WAF management interface
if (not os.environ.get('PYTHONHTTPSVERIFY', '') and
        getattr(ssl, '_create_unverified_context', None)):
    ssl._create_default_https_context = ssl._create_unverified_context


# method to send REST calls
def send_request(method, path, body={}):
    req = urllib2.Request(TARGET_WAF + "/airlock/rest/" + path,
                          body, DEFAULT_HEADERS)
    req.get_method = lambda: method
    r = opener.open(req)
    return r.read()


def terminate_and_exit(text):
    send_request("POST", "session/terminate")
    sys.exit(text)


# create session
send_request("POST", "session/create")


# signal handler
def cleanup(signum, frame):
    terminate_and_exit("Terminate session")


for sig in (SIGABRT, SIGILL, SIGINT, SIGSEGV, SIGTERM):
    signal(sig, cleanup)

# get active config id
resp = json.loads(send_request("GET", "configuration/configurations"))
id = [x["id"] for x in resp["data"]
      if(x['attributes']["configType"] == "CURRENTLY_ACTIVE")][0]

# load active config
send_request("POST", "configuration/configurations/{}/load".format(id))

response = json.loads(send_request("GET", "configuration/mappings"))
if args.allmappings:
    # get all mappings   
    mapping_ids = [x['id'] for x in response['data']]
else:
    # get mapping with correct name
    mapping_ids = [x['id'] for x in response['data']
                     if(x['attributes']['name'] == args.mapping)]

if not mapping_ids:
    terminate_and_exit("Mapping '{}' not found".format(args.mapping))

for mapping_id in mapping_ids:
    data = {
        "meta": {
            "type": "jsonapi.metadata.document"
        },
        "data": {
            "type": "deny-rule-exception",
            "attributes": {
                "parameternamepattern": '(?!.*\${)\#json\#.*'
            }
        }
    }
    # patch the config
    send_request("POST", "configuration/mappings/{}/deny-rule-groups/{}/deny-rules/{}/exception"
                   .format(mapping_id, deny_rule_group_id, deny_rule_id), json.dumps(data))

# activate config
data = {"comment": CONFIG_COMMENT}
send_request("POST", "configuration/configurations/activate", json.dumps(data))

terminate_and_exit(0)
