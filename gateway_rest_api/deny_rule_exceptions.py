#!/usr/bin/env python3

"""
This Python script interacts with Airlock Gateway's REST API for managing the configuration of deny rule groups.
It enables the addition, deletion, and listing of exceptions for deny rule groups through command-line options.

**Requirements**

The script requires a REST API key for Airlock Gateway. This key can be stored in "./api_key.txt" file or
it can directly be provided using the '-k' command-line option.

**Functionality and Commands**
The script contains three main functionalities:

1. add: Add exceptions to a deny rule group.
2. delete: Delete exceptions from a deny rule group.
3. list: List exceptions from a deny rule group.

Each function requires regexes for selecting the deny rule groups and mappings.
The regexes can be specified using the '-G' and '-M' command-line options.

The add and delete functions require an identifier for the exception (-i command-line option).

Moreover, the add function requires a pattern for the exception (-P or -H command-line options):
- `-P` or `--parameter-name-regex`: Specifies a Parameter Name exception.
- `-H` or `--header-name-regex`:  Specifies a Header Name exception.

**Other important options:**

- `-g` or `--gateway`: Specify the gateway address
- `-p` or `--port`: Specify the HTTPS port for the gateway (default is 443)
- `-P` or `--parameter-name-pattern`: Specify a Parameter Name Pattern.
- `-H` or `--header-name-pattern`:  Specify a Header Name Pattern.
- `-M` or `--mapping-regex`:  Select mappings by using a regular expression on the mapping name.
- `-G` or `--group-regex`:  Select deny rule groups by using a regular expression on the group name.
- `-k` or `--api-key`: REST API key for Airlock Gateway.
- `-i` or `--identifier`: Identifier for the exception.
- `-c` or `--comment`: Comment for the change (default is 'Modify exceptions through REST API')
- `-y` or `--assumeyes`: Automatically answer yes for all questions.
- `--activate`: Activate the configuration changes on the gateway, by default the changes will be saved but not activated.

**Examples**
Add an exception to the mapping ^Auth$ in deny rule groups matching SQL, activate the new configuration:
    ./deny_rule_exceptions.py add -g bohol -M '^Auth$' -G SQL -P foo -i 'bar' -c test --activate
Delete the exception 'bar' from the mapping ^Auth$ in deny rule groups matching SQL, activate the new configuration:
    ./deny_rule_exceptions.py delete -g bohol -M '^Auth$' -G SQL -i 'bar' -c test --activate
List exceptions from the mapping ^Auth$ in deny rule groups matching SQL:
    ./deny_rule_exceptions.py list -g bohol -M '^Auth$' -G SQL

"""

from airlock_gateway_rest_api_lib import airlock_gateway_rest_api_lib as al
import signal
import argparse
import logging
import sys
import re
import pprint
import configparser
import os
import click

logging.basicConfig(
    level=logging.DEBUG,
    filename="last_run.log",
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)


def register_cleanup_handler():
    """
    Cleanup handler, will terminate the session if a program error
    occurs at runtime.
    """

    def cleanup(signum, frame):
        al.terminate_session("Terminate session")

    for sig in (
        signal.SIGABRT,
        signal.SIGILL,
        signal.SIGINT,
        signal.SIGSEGV,
        signal.SIGTERM,
    ):
        signal.signal(sig, cleanup)


def add_exception(args, session, pattern, exception_regex):
    """
    Add an exception to a deny rule group and mapping.
    """
    selected_mappings = al.select_mappings(session, args.mapping_regex)
    selected_groups = []
    for dr in al.get_deny_rule_groups(session):
        if re.search(args.group_regex, dr["attributes"]["name"]):
            selected_groups.append(dr)

    print("Selected mappings:")
    [print("\t" + mapping["attributes"]["name"]) for mapping in selected_mappings]
    print("Selected deny-rule groups:")
    [print("\t" + group["attributes"]["name"]) for group in selected_groups]

    if not selected_mappings:
        print("No mappings selected")
        exit(1)
    if not selected_groups:
        print("No deny-rule groups selected")
        exit(1)
    if not args.assumeyes and not click.confirm("Do you want to continue?", default=True):
        exit(1)

    for mapping in selected_mappings:
        for group in selected_groups:
            group_data = al.get_mapping_deny_rule_group(session, mapping["id"], group["id"])
            for exception in group_data["attributes"]["exceptions"]:
                if "parameterNamePattern" in exception and exception["parameterNamePattern"]["name"] == args.identifier:
                    print(
                        f'A parameter name exception with identifier "{args.identifier}" already exists\nin mapping "{mapping["attributes"]["name"]}" and deny-rule group "{group["attributes"]["name"]}"'
                    )
                    print("Use the delete command to remove these exceptions or choose a different identifier")
                    exit(1)

                if "headerNamePattern" in exception and exception["headerNamePattern"]["name"] == args.identifier:
                    print(
                        f'A header name exception with identifier "{args.identifier}" already exists\nin mapping "{mapping["attributes"]["name"]}" and deny-rule group "{group["attributes"]["name"]}"'
                    )
                    print("\nUse the delete command to remove these exceptions or choose a different identifier")
                    exit(1)

    exception = {
        "enabled": True,
        f"{pattern}": {
            "enabled": True,
            "pattern": f"{exception_regex}",
            "name": f"{args.identifier}",
        },
    }
    for mapping in selected_mappings:
        for group in selected_groups:
            group_data = al.get_mapping_deny_rule_group(session, mapping["id"], group["id"])
            exceptions = group_data["attributes"]["exceptions"] + [exception]
            al.update_mapping_deny_rule_group(session, mapping["id"], group["id"], {"exceptions": exceptions})


def delete_exception(args, session):
    """
    Delete an exception from a deny rule group and mapping.
    """
    selected_mappings = al.select_mappings(session, args.mapping_regex)
    selected_groups = []
    for dr in al.get_deny_rule_groups(session):
        if re.search(args.group_regex, dr["attributes"]["name"]):
            selected_groups.append(dr)

    print("Selected mappings:")
    [print("\t" + mapping["attributes"]["name"]) for mapping in selected_mappings]
    print("Selected deny-rule groups:")
    [print("\t" + group["attributes"]["name"]) for group in selected_groups]

    if not selected_mappings:
        print("No mappings selected")
        exit(1)
    if not selected_groups:
        print("No deny-rule groups selected")
        exit(1)
    if not args.assumeyes and not click.confirm("Do you want to continue?", default=True):
        exit(1)

    for mapping in selected_mappings:
        for group in selected_groups:
            group_ids = session, mapping["id"], group["id"]
            deny_rule_group_data = al.get_mapping_deny_rule_group(*group_ids)

            exceptions = deny_rule_group_data["attributes"]["exceptions"]
            pattern = "parameterNamePattern"
            for exception in exceptions:
                if pattern in exception and exception[pattern]["name"] == args.identifier:
                    exceptions.remove(exception)
            pattern = "headerNamePattern"
            for exception in exceptions:
                if pattern in exception and exception[pattern]["name"] == args.identifier:
                    exceptions.remove(exception)

            al.update_mapping_deny_rule_group(*group_ids, {"exceptions": exceptions})


def list_exceptions(args, session):
    """
    List exceptions for specific deny rule groups and mapping.
    """
    selected_mappings = al.select_mappings(session, args.mapping_regex)
    selected_groups = []
    for dr in al.get_deny_rule_groups(session):
        if re.search(args.group_regex, dr["attributes"]["name"]):
            selected_groups.append(dr)

    table = []
    for mapping in selected_mappings:
        for group in selected_groups:
            group_ids = session, mapping["id"], group["id"]
            deny_rule_group_data = al.get_mapping_deny_rule_group(*group_ids)
            exceptions = deny_rule_group_data["attributes"]["exceptions"]
            for exception in exceptions:
                if "parameterNamePattern" in exception:
                    name = exception["parameterNamePattern"]["name"]
                    pattern = exception["parameterNamePattern"]["pattern"]
                    type = "Parameter"
                if "headerNamePattern" in exception:
                    name = exception["headerNamePattern"]["name"]
                    pattern = exception["headerNamePattern"]["pattern"]
                    type = "Header"
                table.append(
                    [
                        mapping["attributes"]["name"],
                        group["attributes"]["name"],
                        type,
                        name,
                        pattern,
                    ]
                )

    if table:
        print("Exceptions:")
        # print the table, without using tabulate
        for row in table:
            print("--------------------")
            print(f"Mapping: {row[0]}")
            print(f"Group: {row[1]}")
            print(f"Type: {row[2]}")
            print(f"Name: {row[3]}")
            print(f"Pattern: {row[4]}")


def main():
    parser = argparse.ArgumentParser()

    subparsers = parser.add_subparsers(required=True)
    parser_add = subparsers.add_parser("add", help="Add exceptions")
    parser_del = subparsers.add_parser("delete", help="Delete exceptions")
    parser_lst = subparsers.add_parser("list", help="List exceptions")

    subparsers.required = True
    subparsers.dest = "command"

    parser_add.add_argument("-g", "--gateway", help="Gateway to activate config on", required=True)
    parser_add.add_argument("-p", "--port", help="Gateway HTTPS port", type=int, default=443)
    parser_add.add_argument("-M", "--mapping-regex", help="Pattern selecting mapping names", required=True)
    parser_add.add_argument("-G", "--group-regex", help="Identifier for the deny rule", required=True)
    parser_add.add_argument("-k", "--api-key", help="REST API key")

    parser_del.add_argument("-g", "--gateway", help="Gateway to activate config on", required=True)
    parser_del.add_argument("-p", "--port", help="Gateway HTTPS port", type=int, default=443)
    parser_del.add_argument("-M", "--mapping-regex", help="Pattern selecting mapping names", required=True)
    parser_del.add_argument("-G", "--group-regex", help="Identifier for the deny rule", required=True)
    parser_del.add_argument("-k", "--api-key", help="REST API key")

    parser_lst.add_argument("-g", "--gateway", help="Gateway to activate config on", required=True)
    parser_lst.add_argument("-p", "--port", help="Gateway HTTPS port", type=int, default=443)
    parser_lst.add_argument("-M", "--mapping-regex", help="Pattern selecting mapping names", required=True)
    parser_lst.add_argument("-G", "--group-regex", help="Identifier for the deny rule", required=True)
    parser_lst.add_argument("-k", "--api-key", help="REST API key")

    parse_pattern = parser_add.add_mutually_exclusive_group(required=True)
    parse_pattern.add_argument("-P", "--parameter-name-pattern", help="Parameter Name Pattern")
    parse_pattern.add_argument("-H", "--header-name-pattern", help="Header Name Pattern")

    parser_add.add_argument("-i", "--identifier", help="Identifier for the exception", required=True)
    parser_del.add_argument("-i", "--identifier", help="Identifier for the exception", required=True)
    parser_add.add_argument("-c", "--comment", help="Comment for the change", default="Modify exceptions with REST API")
    parser_del.add_argument("-c", "--comment", help="Comment for the change", default="Modify exceptions with REST API")
    parser_add.add_argument("-y", "--assumeyes", help="Automatically answer yes for all questions", action="store_true")
    parser_del.add_argument("-y", "--assumeyes", help="Automatically answer yes for all questions", action="store_true")
    parser_add.add_argument("--activate", help="Activate configuration", action="store_true")
    parser_del.add_argument("--activate", help="Activate configuration", action="store_true")

    args = parser.parse_args()

    if args.api_key:
        api_key = args.api_key
    elif os.path.exists("api_key.conf"):
        config = configparser.ConfigParser()
        config.read("api_key.conf")
        api_key = config.get("KEY", "api_key")
    else:
        sys.exit("API key needed, either with -k flag or in a api_key.conf file")

    try:
        session = al.create_session(args.gateway, api_key, args.port)
    except Exception as e:
        print(f"There was an error creating the session: are the gateway URL, port and API key valid?")
        sys.exit(1)

    gw_version = al.get_version(session)
    if gw_version != "8.1":
        print(f"Gateway version {gw_version} is not supported. Please use version 8.1")
        sys.exit(1)

    register_cleanup_handler()

    # Makes sure the loaded configuration matches the currently active one.
    al.load_active_config(session)

    # Save backup of original config file
    # al.export_current_config_file(session, "./config.zip")

    if args.command == "add":
        if args.parameter_name_pattern:
            pattern = "parameterNamePattern"
            exception_regex = args.parameter_name_pattern
        elif args.header_name_pattern:
            pattern = "headerNamePattern"
            exception_regex = args.header_name_pattern
        add_exception(args, session, pattern, exception_regex)
        print("Saving configuration...")
        al.save_config(session, f"{args.comment}")
        if args.activate:
            print("Activating configuration...")
            al.activate(session, f"{args.comment}")
    elif args.command == "delete":
        delete_exception(args, session)
        print("Saving configuration...")
        al.save_config(session, f"{args.comment}")
        if args.activate:
            print("Activating configuration...")
            al.activate(session, f"{args.comment}")
    elif args.command == "list":
        list_exceptions(args, session)

    # This line doesn't do anything as we never activated any config,
    # but in general this is how you restore the backup that you stored
    # at the beginning of the script.
    # al.import_config(session, "./config.zip")

    al.terminate_session(session)


if __name__ == "__main__":
    main()
