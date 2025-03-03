#!/usr/bin/env python3
# coding=utf-8
"""
IP List Management on Airlock Gateway Versions 8.3.2 and later.

This script supports three operations:
  1. list   : Lists all IP address lists (with IDs and IPs).
  Usage:
      ./ip_list_relationships.py list -g <HOSTNAME> [-p <PORT>] [-k <API_KEY>]

  2. update : Updates an IP list’s relationships. Two update modes are supported:
       --blacklist: Update the blacklist via the explicit endpoint.
       --whitelist: Update the whitelist for all mappings matching a regex.
                    For each mapping, the script patches its ipRules.ipAddressWhitelists
                    by appending a new entry (or extending an existing one) that includes
                    the provided IP list ID and a path pattern.

After performing the updates, the script prompts (unless --assumeyes is given) and then activates the configuration.

API key is provided via the -k/--api-key flag or read from an "api_key.conf" file (with a [KEY] section).

Usage Examples:
  List IP address lists:
      ./ip_list_relationships.py list -g mywaf.example.com -k YOUR_API_KEY

  Update blacklist:
      ./ip_list_relationships.py update -g mywaf.example.com -I 3 --blacklist -M '^cust' -y -c "Add blacklist entries" -k YOUR_API_KEY

  Update whitelist (requires --path-pattern or -P):
      ./ip_list_relationships.py update -g mywaf.example.com -I 3 --whitelist -M '^cust' -P 'testpath' -c "Add whitelist entries" -k YOUR_API_KEY
"""

import sys
import os
import argparse
import configparser
import logging
import signal
import re
import json

from airlock_gateway_rest_api_lib.src.airlock_gateway_rest_api_lib import airlock_gateway_rest_api_lib as al

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)

SESSION = None
DEFAULT_API_KEY_FILE = "api_key.conf"

def terminate_with_error(message=None):
    if message:
        print(message)
    if SESSION:
        al.terminate_session(SESSION)
    sys.exit(1)

def register_cleanup_handler():
    def cleanup(signum, frame):
        if SESSION:
            al.terminate_session(SESSION)
        sys.exit("Session terminated due to signal.")
    for sig in (signal.SIGABRT, signal.SIGILL, signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, cleanup)

def get_api_key(args, key_file=DEFAULT_API_KEY_FILE):
    if args.api_key:
        return args.api_key.strip()
    elif os.path.exists(key_file):
        config = configparser.ConfigParser()
        config.read(key_file)
        try:
            return config.get("KEY", "api_key").strip()
        except Exception as e:
            sys.exit(f"Error reading API key from {key_file}: {e}")
    else:
        sys.exit("API key needed, either via -k option or in an api_key.conf file.")

def list_ip_lists(session):
    res = al.get(session, "/configuration/ip-address-lists", exp_code=200)
    ip_lists = res.json().get("data")
    if not ip_lists:
        print("No IP address lists found.")
    else:
        for ip in ip_lists:
            attrs = ip.get("attributes", {})
            print(f"ID: {ip.get('id')}, Name: {attrs.get('name')}, IPs: {attrs.get('ips')}")
    return

def update_blacklist(session, ip_list_id: str, mapping_regex: str, force: bool) -> dict:
    """
    Updates the IP blacklist for the given IP list by selecting mappings
    matching the provided regex and appending them as mapping references.
    """
    mappings = al.select_mappings(session, pattern=mapping_regex)
    if not mappings:
        terminate_with_error("No mappings found matching the regex.")

    new_entries = []
    mapping_refs = []
    for mapping in mappings:
        entry = {"type": "mapping", "id": mapping["id"]}
        if entry not in mapping_refs:
            mapping_refs.append(entry)
            new_entries.append(entry)

    if not new_entries:
        print("No new mapping entries to add.")
        return {}

    payload = {"data": mapping_refs}

    if not force:
        print(f"About to update IP list {ip_list_id} blacklist with these mapping IDs:")
        for entry in new_entries:
            print(f"  {entry['id']}")
        ans = input("Continue with update? [y/n] ")
        if ans.lower() != "y":
            terminate_with_error("Operation cancelled.")

    endpoint = f"/configuration/ip-address-lists/{ip_list_id}/relationships/mappings-blacklist"
    res = al.patch(session, endpoint, payload, exp_code=[204,404])
    if res.status_code == 204:
        print("IP blacklist updated successfully.")
    else:
        print("Failed to update IP blacklist.")

def update_whitelist(session, ip_list_id: str, mapping_regex: str, path_pattern: str, force: bool) -> dict:
    """
    For all mappings matching the provided regex, update each mapping’s
    ipRules.ipAddressWhitelists by either appending a new whitelist entry or
    extending an existing entry.
    
    If an entry with the same path pattern exists, its ipAddressListIds array is
    extended with the given ip_list_id (if not already present).
    Returns a result dictionary containing a list of updated mapping names.
    """
    selected_mappings = al.select_mappings(session, pattern=mapping_regex)
    if not selected_mappings:
        terminate_with_error("No mappings found matching the regex.")

    updated = []
    for mapping in selected_mappings:
        mapping_id = mapping["id"]
        m = al.get_mapping_by_id(session, mapping_id)
        attrs = m.get("attributes", {})
        ip_rules = attrs.get("ipRules", {})
        whitelist = ip_rules.get("ipAddressWhitelists", {})
        if not whitelist or not isinstance(whitelist, dict):
            whitelist = {"logOnly": False, "pathWhitelists": []}
        path_whitelists = whitelist.get("pathWhitelists", [])
        if not isinstance(path_whitelists, list):
            path_whitelists = []

        ip_id = int(ip_list_id)
        found_entry = None
        for entry in path_whitelists:
            if entry.get("pathPattern", {}).get("pattern") == path_pattern:
                found_entry = entry
                break

        if found_entry:
            current_ids = found_entry.get("ipAddressListIds", [])
            if ip_id not in current_ids:
                current_ids.append(ip_id)
                found_entry["ipAddressListIds"] = current_ids
                print(f"Mapping '{attrs.get('name')}' (ID: {mapping_id}): Extended whitelist entry for path '{path_pattern}' with IP list ID {ip_list_id}.")
            else:
                print(f"Mapping '{attrs.get('name')}' (ID: {mapping_id}) already contains IP list ID {ip_list_id} for path '{path_pattern}'.")
        else:
            new_entry = {
                "enabled": True,
                "pathPattern": {
                    "pattern": path_pattern,
                    "caseIgnored": False,
                    "inverted": False
                },
                "ipAddressListIds": [ip_id]
            }
            path_whitelists.append(new_entry)
            print(f"Mapping '{attrs.get('name')}' (ID: {mapping_id}): Added new whitelist entry for path '{path_pattern}' with IP list ID {ip_list_id}.")
        
        whitelist["pathWhitelists"] = path_whitelists
        ip_rules["ipAddressWhitelists"] = whitelist
        update_attrs = {"ipRules": ip_rules}
        if al.update_mapping(session, mapping_id, update_attrs):
            updated.append(attrs.get("name"))
            print(f"Mapping '{attrs.get('name')}' (ID: {mapping_id}) updated successfully.")
        else:
            print(f"Failed to update mapping '{attrs.get('name')}' (ID: {mapping_id}).")
    
    return {"updated_mappings": updated}

def main():
    parser = argparse.ArgumentParser(
        description="Manage IP address lists on Airlock Gateway: list IP lists, update blacklists, or update whitelists."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcommand: list
    parser_list = subparsers.add_parser("list", help="List all IP address lists")
    parser_list.add_argument("-g", "--gateway", required=True,
                             help="Airlock Gateway hostname")
    parser_list.add_argument("-k", "--api-key", help="REST API key for Airlock Gateway")
    parser_list.add_argument("-p", "--port", type=int, default=443,
                             help="Gateway HTTPS port (default: 443)")

    # Subcommand: update
    parser_update = subparsers.add_parser("update", help="Update IP list relationships")
    parser_update.add_argument("-g", "--gateway", required=True,
                               help="Airlock Gateway hostname")
    parser_update.add_argument("-k", "--api-key", help="REST API key for Airlock Gateway")
    parser_update.add_argument("-p", "--port", type=int, default=443,
                               help="Gateway HTTPS port (default: 443)")
    parser_update.add_argument("-I", "--ip-list-id", required=True,
                               help="ID of the IP address list to update")
    group = parser_update.add_mutually_exclusive_group(required=True)
    group.add_argument("--blacklist", action="store_true",
                       help="Update the blacklist (uses /relationships/mappings-blacklist)")
    group.add_argument("--whitelist", action="store_true",
                       help="Update the whitelist (updates each mapping's ipRules.ipAddressWhitelists)")
    parser_update.add_argument("-M", "--mapping-regex", required=True,
                               help="Regex pattern to select mappings by name")
    parser_update.add_argument("-P", "--path-pattern",
                               help="(Required for whitelist updates) Path pattern for the whitelist entry")
    parser_update.add_argument("-y", "--assumeyes", action="store_true",
                               help="Automatically confirm without prompting")
    parser_update.add_argument("-c", "--comment", default="Update IP list relationships via REST API",
                               help="Comment for the configuration change")
    args = parser.parse_args()

    global SESSION
    api_key = get_api_key(args)
    SESSION = al.create_session(args.gateway, api_key, args.port)
    if not SESSION:
        sys.exit("Could not create session. Check gateway, port, and API key.")
    register_cleanup_handler()
    al.load_active_config(SESSION)

    if args.command == "list":
        list_ip_lists(SESSION)
    elif args.command == "update":
        if args.blacklist:
            result = update_blacklist(SESSION, args.ip_list_id, args.mapping_regex, args.assumeyes)
            print(json.dumps(result, indent=4))
        elif args.whitelist:
            if not args.path_pattern:
                sys.exit("For whitelist updates, --path-pattern is required.")
            result = update_whitelist(SESSION, args.ip_list_id, args.mapping_regex, args.path_pattern, args.assumeyes)
            print(json.dumps(result, indent=4))
        else:
            sys.exit("Unsupported update type.")

        if not args.assumeyes:
            ans = input("\nContinue to activate the new configuration? [y/n] ")
            if ans.lower() != "y":
                al.save_config(SESSION, args.comment)
                print("Configuration saved, but not activated.")
        if al.activate(SESSION, args.comment):
            print("Configuration activated successfully.")
        else:
            al.save_config(SESSION, args.comment)
            print("Configuration saved.")
    else:
        sys.exit("Unsupported command.")

    al.terminate_session(SESSION)

if __name__ == "__main__":
    main()
