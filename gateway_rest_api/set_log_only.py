#!/usr/bin/env python3
# coding=utf-8
"""
Version 1.1
Script to activate a Rule in
log-only mode on all specified mappings.
All actions operate on the newest saved or active 
configuration and will save a new configuration.

Example:

Activate log only for rule TI_001a on all mappings containing
the string 'basic' on system aldea

./set_log_only.py -k api_key -n aldea -r -2170 -m 'basic'

to find out the rule id use the following shell comand 
on airlock

NAME=TI_001c; grep -P -B1 "\.Name=.*$NAME" /opt/airlock/mgt-agent/conf/default-patterns/denyRuleFactoryDefaults.properties | awk -F= '/Id=/ { print $2 }'

Tested with:
- Airlock Gateway 7.7
"""

from cgitb import enable
from urllib import request
import ssl
import json
import os
import sys
import re
from argparse import ArgumentParser
from http.cookiejar import CookieJar
import signal
from zipfile import ZipFile
from io import BytesIO
import xml.etree.ElementTree as ET

DEFAULT_API_KEY_FILE = "./api_key"

parser = ArgumentParser()
parser.add_argument("-n", dest="host", metavar="hostname",
                    required=True,
                    help="Airlock Gateway hostname")
parser.add_argument("-r", dest="rule_id", metavar="rule_id",
                    required=True,
                    help="Deny Rule ID")
group_sel = parser.add_mutually_exclusive_group(required=True)
group_sel.add_argument("-m", dest="mapping_selector_pattern",
                       metavar="pattern",
                       help="Pattern matching mapping name, e.g. ^mapping_a$")
group_sel.add_argument("-l", dest="mapping_selector_label", metavar="label",
                       help="Label for mapping selection")

parser.add_argument("-f", dest="confirm", action="store_false",
                    help="Force, no confirmation needed")
parser.add_argument("-d", dest="activate", action="store_false",
                    help="disabled log-only")
parser.add_argument("-k", dest="api_key_file", metavar="api_key_file",
                    default=DEFAULT_API_KEY_FILE,
                    help="Path to API key file "
                    f"(default {DEFAULT_API_KEY_FILE})")




args = parser.parse_args()
sys.tracebacklimit = 0

TARGET_GATEWAY = f'https://{args.host}'
CONFIG_XML_NAME = "alec_table.xml"

try:
    api_key = open(args.api_key_file, 'r').read().strip()
except (IOError, FileNotFoundError) as error:
    print(f'Can not read API key from {args.api_key_file}')
    sys.exit(-1)

DEFAULT_HEADERS = {"Authorization": f'Bearer {api_key}'}

# we need a cookie store
opener = request.build_opener(request.HTTPCookieProcessor(CookieJar()))

# ignore invalid SSL cert on the management interface
if (not os.environ.get('PYTHONHTTPSVERIFY', '') and
        getattr(ssl, '_create_unverified_context', None)):
    ssl._create_default_https_context = ssl._create_unverified_context


# method to send REST calls
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
    req = request.Request(TARGET_GATEWAY + "/airlock/rest/" + path,
                          body, DEFAULT_HEADERS)
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
    return sorted(resp, key=lambda x: x['attributes']['name'])


def get_mappings():
    # filter mappings
    return ([
        {'id': x['id'],
         'name': x['attributes']['name'],
         'ip_rules': x['attributes']['ipRules']}
        for x in get_all_mappings() if (
            args.mapping_selector_pattern and
            re.search(args.mapping_selector_pattern,
                      x['attributes']['name']) or
            args.mapping_selector_label in x['attributes']['labels']
        )
    ])


def create_change_info(affected_mapping_names):
    if args.activate:
        change_info = 'Log-only for rule {} enabled'.format(args.rule_id)
    else:    
        change_info = 'Log-only for rule {} removed'.format(args.rule_id)

    change_info += ' for the following mapping(s): \n\t{}'\
                   .format('\n\t'.join(affected_mapping_names))
    return change_info


def export_mappings(mappings):
    mapping_xmls = []
    for mapping in mappings:
        resp = send_request(method="GET",
                            path="configuration/mappings/{}/export".format(
                                mapping['id']),
                            accept_header="application/zip")
        z = ZipFile(BytesIO(resp))
        mapping_xml = z.open(CONFIG_XML_NAME).read()
        mapping_xmls.append(mapping_xml)
    return mapping_xmls

def modify_mappings(mapping_xmls):
    new_mapping_xmls = []
    for mapping_xml in mapping_xmls:
        doc = ET.fromstring(mapping_xml)
        mapping_name = doc.find('./Mappings/Mapping/Name').text

        rules = doc.findall('.//DenyRuleUsage')
        rule = None
        for r in rules:
            if r.findtext('DenyRuleId') == args.rule_id:
                rule = r
        if rule == None:
            print ("No deny Rule found with Id: {}".format(args.rule_id))
            terminate_and_exit()

        enabled = rule.find('.//Enabled')
        log_only = rule.find('.//LogOnly')
        if args.activate:
            enabled.text = 'true'
            log_only.text = 'true'
        else:
            enabled.text = 'false'
            log_only.text = 'false'

        new_mapping_xmls.append(ET.tostring(doc))
    return new_mapping_xmls


def upload_mappings(mapping_xmls):
    for mapping_xml in mapping_xmls:
        mapping_zip = BytesIO()
        with ZipFile(mapping_zip, mode="w") as zf:
            zf.writestr(CONFIG_XML_NAME, mapping_xml)

        mapping_zip.seek(0)

        send_request(method="PUT",
                     path="configuration/mappings/import",
                     body=mapping_zip.read(),
                     content_type="application/zip")


def get_mapping_names(mapping_xmls):
    mapping_names = []
    for mapping_xml in mapping_xmls:
        doc = ET.fromstring(mapping_xml)
        mapping_name = doc.find('./Mappings/Mapping/Name').text
        mapping_names.append(mapping_name)
    return sorted(mapping_names)


def confirm(change_info):
    if not args.confirm:
        return True
    print(change_info)
    if input('\nContinue to save the config? [y/n] ') == 'y':
        return True
    print("Nothing changed")
    return False


def save_config(change_info):
    data = {"comment": "REST: " + change_info.replace('\n\t', ', ')
                                             .replace(': ,', ':')}

    # save config
    send_request("POST", "configuration/configurations/save", json.dumps(data))
    print(f"\nConfig saved with comment: {data['comment']}")


# create session
send_request("POST", "session/create")
register_cleanup_handler()

# load last config (active or saved)
load_last_config()

# filter mappings
mappings = get_mappings()
if not mappings:
    terminate_and_exit("No mapping found - exit")


mapping_xmls = export_mappings(mappings)
modified_mapping_xmls = modify_mappings(mapping_xmls)
upload_mappings(modified_mapping_xmls)
affected_mapping_names = get_mapping_names(modified_mapping_xmls)

change_info = create_change_info(affected_mapping_names)
confirm(change_info) or terminate_and_exit(0)
save_config(change_info)

terminate_and_exit(0)


