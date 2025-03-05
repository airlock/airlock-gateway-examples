#!/usr/bin/env python3
# coding=utf-8
"""
Script to manage IP list usages
and to remove allow rule IP pattern
All actions operate on the newest saved or active configuration
and will save a new configuration.
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
from zipfile import ZipFile
from io import BytesIO
import xml.etree.ElementTree as ET

DEFAULT_API_KEY_FILE = "./api_key"

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
group_action.add_argument("-d", dest="action", action="store_const",
                          const="delete",
                          help="Delete IP Pattern in allow rule")
group_sel = parser.add_mutually_exclusive_group(required=True)
group_sel.add_argument("-m", dest="mapping_selector_pattern",
                       metavar="pattern",
                       help="Pattern matching mapping name, e.g. ^mapping_a$")
group_sel.add_argument("-l", dest="mapping_selector_label", metavar="label",
                       help="Label for mapping selection")
parser.add_argument("-i", dest="iplist", metavar="pattern",
                    help="Pattern matching IP list, e.g. ^IP-list99$")

group_type = parser.add_mutually_exclusive_group(required=False)
group_type.add_argument("-w", dest="blacklist", action="store_false",
                        help="Modify whitelist", default=None)
group_type.add_argument("-b", dest="blacklist", action="store_true",
                        help="Modify blacklist", default=None)

parser.add_argument("-o", dest="log_only",
                    choices=['enable', 'disable'],
                    help="Enable/disable 'log only' on all affected "
                    "mappings for the specified IP list type")
parser.add_argument("-f", dest="confirm", action="store_false",
                    help="Force, no confirmation needed")
parser.add_argument("-k", dest="api_key_file", metavar="api_key_file",
                    default=DEFAULT_API_KEY_FILE,
                    help="Path to API key file "
                    f"(default {DEFAULT_API_KEY_FILE})")

parser.add_argument("-t", dest="allow_rule_title",
                    default="Allow all",
                    help="New title for the modified allow rule")


args = parser.parse_args()
sys.tracebacklimit = 0

if args.action in ['add', 'remove'] and not (args.iplist or args.log_only):
    parser.error("IP list (-i) required for 'add' or 'remove' action"
                 " if log-only is not specified")

if args.action in ['add', 'remove', 'show'] and args.blacklist is None:
    parser.error("blacklist or whitelist (-w / -b) not specified")

TARGET_GATEWAY = f'https://{args.host}'

CONFIG_XML_NAME = "alec_table.xml"
DEFAULT_ALLOW_RULE_IP_PATTERN_ID = "-100"
DEFAULT_ALLOW_RULE_IP_PATTERN_NODE = """
                    <IpPattern>
                        <Name>(default) No Restriction</Name>
                        <Comment>All IP addresses.
The empty pattern matches any string.</Comment>
                        <Active>false</Active>
                        <Pattern>
                            <PatternString></PatternString>
                            <IgnoreCase>false</IgnoreCase>
                            <InvertPattern>false</InvertPattern>
                            <AirlockRegexFormat>true</AirlockRegexFormat>
                        </Pattern>
                        <DefaultId>-100</DefaultId>
                    </IpPattern>

"""


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
            'log_only': mapping['ip_rules']
                               [f'ipAddress{list_type.title()}']
                               ['logOnly'],
            'ip_lists': []
        }

    resp_al = send_request("GET", "/configuration/ip-address-lists")
    for r in json.loads(resp_al)['data']:
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


def patch_log_only(mappings, list_type):
    for mapping in mappings:
        data = {
            "data": {
                "attributes": {
                    "ipRules": {
                        f"ipAddress{list_type.title()}": {
                            "logOnly": True if args.log_only == 'enable'
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


def patch_usage(mappings, list_type, ip_lists):
    for mapping in mappings:
        selected_ip_list = []
        for ip_list in ip_lists:
            selected_ip_list.append({"id": ip_list['id'],
                                     "type": "ip-address-list"})

        data = {"data": selected_ip_list}
        method = "PATCH" if args.action == 'add' else "DELETE"
        send_request(method,
                     "configuration/mappings/{}/relationships/ip-address-{}"
                     .format(mapping['id'], list_type), json.dumps(data))


def create_change_info(affected_mapping_names, list_type, ip_lists):
    change_info = ''
    if args.action == "add":
        change_info += "Add IP list"
    elif args.action == "remove":
        change_info += "Remove IP list"
    elif args.action == "delete":
        change_info += "Remove IP pattern in allow rules"

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


def changeTitle(allowRuleElement, title_index):
    name = allowRuleElement.find('Name')
    suffix = "" if title_index == 1 else f" {title_index}"
    name.text = args.allow_rule_title + suffix
    return name.text


def modify_mappings(mapping_xmls):
    new_mapping_xmls = []
    ip_default_pattern = ET.fromstring(DEFAULT_ALLOW_RULE_IP_PATTERN_NODE)
    for mapping_xml in mapping_xmls:
        doc = ET.fromstring(mapping_xml)
        mapping_name = doc.find('./Mappings/Mapping/Name').text
        allow_rules = doc.find('.//AllowRules')
        title_index = 1
        for allow_rule in allow_rules:
            allow_rule_name = allow_rule.find('./Name').text
            ip_pattern = allow_rule.find('./IpPattern')
            ip_pattern_id = ip_pattern.find('.//DefaultId')
            if ip_pattern_id.text != DEFAULT_ALLOW_RULE_IP_PATTERN_ID:
                pattern_name = ip_pattern.find('./Name').text
                ip_pattern.clear()
                ip_pattern.extend(ip_default_pattern)
                new_title = changeTitle(allow_rule, title_index)
                title_index += 1
                print(f"In mapping '{mapping_name}' "
                      f"allow rule name '{allow_rule_name}' "
                      f"changed to '{new_title}' "
                      f"and IP pattern '{pattern_name}' removed")
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

# filter ip lists
ip_lists = []
if args.iplist:
    ip_lists = get_ip_lists()
    if not ip_lists:
        terminate_and_exit("No IP list found")

list_type = "blacklists" if args.blacklist else "whitelists"

if args.action == "show":
    show_usages(mappings, list_type)
else:
    if args.log_only:
        patch_log_only(mappings, list_type)
    if args.action in ['add', 'remove']:
        patch_usage(mappings, list_type, ip_lists)
    affected_mapping_names = sorted(x['name'] for x in mappings)

    if args.action == "delete":
        mapping_xmls = export_mappings(mappings)
        modified_mapping_xmls = modify_mappings(mapping_xmls)
        upload_mappings(modified_mapping_xmls)
        affected_mapping_names = get_mapping_names(modified_mapping_xmls)

    if (affected_mapping_names):
        change_info = create_change_info(affected_mapping_names, list_type,
                                         ip_lists)
        confirm(change_info) or terminate_and_exit(0)
        save_config(change_info)
    else:
        print("Nothing to do (no mappings affected)")

terminate_and_exit(0)
