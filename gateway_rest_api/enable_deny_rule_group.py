#!/usr/bin/env python3
"""
Script to enable or disable a deny rule group on all mappings using
the Airlock REST API library (airlock_gateway_rest_api_lib.py).

Usage example:
    ./enable_deny_rule_group.py -g mywaf.example.com -G SQL_005A -a enable -k <YOUR_API_KEY>
    
If -k is not provided, the script will try to read the API key from "api_key.conf"
with a [KEY] section and an "api_key" value.

Tested with Airlock Gateway 8.3
"""

import sys
import os
import argparse
import configparser
import logging
import signal

from airlock_gateway_rest_api_lib.src.airlock_gateway_rest_api_lib import airlock_gateway_rest_api_lib as al

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)

# Global session variable
SESSION = None

def terminate_with_error(message=None):
    """Terminate the session and exit with an error message."""
    if message:
        print(message)
    al.terminate_session(SESSION)
    sys.exit(1)

def register_cleanup_handler():
    """
    Cleanup handler, will terminate the session if a program error
    occurs at runtime.
    """
    def cleanup(signum, frame):
        al.terminate_session(SESSION)
        sys.exit("Session terminated due to signal.")
    for sig in (signal.SIGABRT, signal.SIGILL, signal.SIGINT,
                signal.SIGSEGV, signal.SIGTERM, signal.SIGQUIT):
        signal.signal(sig, cleanup)

def main():
    parser = argparse.ArgumentParser(
        description="Enable or disable a deny rule group on all WAF mappings."
    )
    parser.add_argument("-g", "--gateway", required=True,
                        help="Airlock WAF hostname")
    parser.add_argument("-G", "--deny-rule-group-id", required=True,
                        help="Deny Rule Group ID (shortname)")
    parser.add_argument("-a", "--action", choices=['enable', 'disable'],
                        default='enable', help="Enable or disable the deny rule group")
    parser.add_argument("-p", "--port", type=int, default=443,
                        help="Gateway HTTPS port (default: 443)")
    parser.add_argument("-k", "--api-key", help="REST API key for Airlock Gateway")
    args = parser.parse_args()

    # Get API key: either from command-line or from config file
    if args.api_key:
        api_key = args.api_key.strip()
    elif os.path.exists("api_key.conf"):
        config = configparser.ConfigParser()
        config.read("api_key.conf")
        try:
            api_key = config.get("KEY", "api_key").strip()
        except Exception as e:
            sys.exit("Error reading API key from api_key.conf: " + str(e))
    else:
        sys.exit("API key needed, either via -k option or in an api_key.conf file.")

    # Create a new session
    global SESSION
    SESSION = al.create_session(args.gateway, api_key, args.port)
    if not SESSION:
        sys.exit("Could not create session. Check gateway, port, and API key.")

    register_cleanup_handler()

    # Load the currently active configuration
    al.load_active_config(SESSION)

    # Get all mappings from the gateway
    mappings = al.get_all_mappings(SESSION)
    if not mappings:
        terminate_with_error("No mappings found.")

    enable_flag = True if args.action == "enable" else False

    # For each mapping, update the deny rule group settings
    for mapping in mappings:
        mapping_id = mapping['id']
        mapping_drg = al.get_mapping_deny_rule_group(
            SESSION,
            mapping_id,
            args.deny_rule_group_id
        )
        print(mapping_drg)
        mapping_drg['attributes']['enabled'] = enable_flag
        success = al.update_mapping_deny_rule_group(
            SESSION,
            mapping_id,
            args.deny_rule_group_id,
            mapping_drg['attributes']
        )
        if success:
            print(f"Updated mapping '{mapping['attributes']['name']}', mapping ID: {mapping_id}")
        else:
            print(f"Failed to update mapping '{mapping['attributes']['name']}' , mapping ID: {mapping_id}")

    # Activate the configuration with a comment
    config_comment = f"Script: {args.action} deny rule group {args.deny_rule_group_id} for all mappings."
    if al.activate(SESSION, config_comment):
        print("Configuration activated successfully.")
    else:
        print("Failed to activate configuration.")

    # Terminate the session
    al.terminate_session(SESSION)

if __name__ == "__main__":
    main()
