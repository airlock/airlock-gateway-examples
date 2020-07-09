#!/usr/bin/env python2
# coding=utf-8

# demo script to activate maintenance page on a WAF mapping

# missing 
# - extended error handling
# - retry handling
# - return status

# configure the API key here
API_KEY_FILE="./api_key"

#######################################################################################

import urllib2
import ssl
import json
import os
import sys
from argparse import ArgumentParser
from cookielib import CookieJar

parser = ArgumentParser(add_help=False)
parser.add_argument("-h", dest="host", metavar="<WAF hostname>", required=True,
        help="Alrock WAF hostname")
parser.add_argument("-m", dest="mapping", metavar="<mapping name>", required=True,
        help="Logical name of the WAF mapping")
parser.add_argument("-a", choices=['enable', 'disable'], dest="action", required=True,
        help="Enable or disable maintenance page")

args = parser.parse_args()

TARGET_WAF="https://{}".format(args.host)
CONFIG_COMMENT = "Script: set maintenance page for mapping {} to {}".format(args.mapping, args.action)

api_key = open(API_KEY_FILE, 'r').read().strip()
DEFAULT_HEADERS = { 	"Accept": "application/json",
                        "Content-Type": "application/json",
                        "Authorization": "Bearer {}".format(api_key) }


# we need a cookie store
cj = CookieJar()
opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj))

# only necessary if you have configured an invalid SSL cert on the WAF management interface
if (not os.environ.get('PYTHONHTTPSVERIFY', '') and
    getattr(ssl, '_create_unverified_context', None)): 
    ssl._create_default_https_context = ssl._create_unverified_context

# method to send REST calls
def send_request(method, path, body={}):
	req = urllib2.Request(TARGET_WAF + path, body, DEFAULT_HEADERS)
	req.get_method = lambda: method
	r = opener.open(req)
	return r.read()

# create session
send_request("POST", "/airlock/rest/session/create")

# get active config id
resp = json.loads(send_request("GET", "/airlock/rest/configuration/configurations"))
id =  [x["id"] for x in resp["data"] if(x['attributes']["configType"] == "CURRENTLY_ACTIVE")][0]

# load active config
send_request("POST", "/airlock/rest/configuration/configurations/{}/load".format(id))

# get all mappings
resp = json.loads(send_request("GET", "/airlock/rest/configuration/mappings"))

# get mapping with correct name
m_ids = [x['id'] for x in resp['data'] if(x['attributes']['name'] == args.mapping)]

if not m_ids:
    sys.exit("Mapping '{}' not found".format(args.mapping))
else:
    mapping_id = m_ids[0]

enable_maintenance_page = "true" if args.action == "enable" else "false"

data = {
        "data" : {
            "attributes" : {
                "enableMaintenancePage" : enable_maintenance_page
                },
            "id": mapping_id,
            "type": "mapping"
            }
        }

# patch the config
send_request("PATCH", "/airlock/rest/configuration/mappings/{}".format(mapping_id), json.dumps(data))


data = { "comment" : CONFIG_COMMENT }
# save config
#send_request("POST", "/airlock/rest/configuration/configurations/save", json.dumps(data))

# activate config
send_request("POST", "/airlock/rest/configuration/configurations/activate", json.dumps(data))
