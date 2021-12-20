#!/usr/bin/env python3
# coding=utf-8
"""
version 2.1
Script to activate maintenance page on a WAF mapping
"""

# file to store REST API key
API_KEY_FILE = "./api_key"

import requests
import ssl
import json
import os
import sys
from argparse import ArgumentParser
from http.cookiejar import CookieJar
from signal import *

parser = ArgumentParser(add_help=False)
parser.add_argument("-h", dest="host", metavar="<WAF hostname>",
                    required=True, help="Airlock WAF hostname")
parser.add_argument("-m", dest="mapping", metavar="<mapping name>",
                    required=True, help="Logical name of the WAF mapping")
parser.add_argument("-a", choices=['enable', 'disable'], dest="action",
                    required=True, help="Enable or disable maintenance page")

args = parser.parse_args()

# Define constants.
api_key = open(API_KEY_FILE, 'r').read().strip()
TARGET_WAF = "https://{}".format(args.host)
REST_URL = TARGET_WAF + "/airlock/rest"
CONFIG_COMMENT = "Script: set maintenance page "\
    "for mapping {} to {}".format(args.mapping, args.action)
DEFAULT_HEADERS = {"Accept": "application/json",
                   "Content-Type": "application/json",
                   "Authorization": "Bearer {}".format(api_key)}


def terminate_and_exit(text):
    session.post(url=REST_URL+"/session/terminate")
    sys.exit(text)
# signal handler
def cleanup(signum, frame):
    terminate_and_exit("Terminate session")


for sig in (SIGABRT, SIGILL, SIGINT, SIGSEGV, SIGTERM):
    signal(sig, cleanup)


# Create Session
session = requests.Session()
session.hooks = {
   'response': lambda r, *args, **kwargs: r.raise_for_status()
}
session.verify = False
requests.packages.urllib3.disable_warnings()
session.headers = DEFAULT_HEADERS
# We use a CookieJar to store and reflect the Cookies received from Airlock
session.cookies = CookieJar()

# Start session
response = session.post(url=REST_URL+"/session/create")

# get active config id
response = session.get(url=REST_URL+"/configuration/configurations")
response = json.loads(response.text)
id = [x["id"] for x in response["data"]
        if(x['attributes']["configType"] == "CURRENTLY_ACTIVE")][0]

# load active config
session.post(url=REST_URL+"/configuration/configurations/{}/load".format(id))

# get all mappings
response = session.get(REST_URL+"/configuration/mappings")
response = response.json()

# get mapping with correct name
m_ids = [x['id'] for x in response['data']
         if(x['attributes']['name'] == args.mapping)]


if not m_ids:
    terminate_and_exit("Mapping '{}' not found".format(args.mapping))
else:
    mapping_id = m_ids[0]

enable_maintenance_page = "true" if args.action == "enable" else "false"

data = {
    "data": {
        "attributes": {
            "enableMaintenancePage": enable_maintenance_page
        },
        "id": mapping_id,
        "type": "mapping"
    }
}
# patch the config
session.patch(REST_URL+"/configuration/mappings/{}"
              .format(mapping_id), data=json.dumps(data))

data = {"comment": CONFIG_COMMENT}

# activate config
session.post(REST_URL+"/configuration/configurations/activate",
             data=json.dumps(data))

terminate_and_exit(0)
