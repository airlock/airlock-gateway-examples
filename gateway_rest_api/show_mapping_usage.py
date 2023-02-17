#!/usr/bin/env python3

# Prints Airlock Gateway mapping usage to stdout based on elasticsearch access logs
# May be very slow and CPU intensive depending on the airlock-elasticsearch-query command speed
# Must be run on the Airlock Gateway host itself. Use at your own risk
# Tested with Airlock Gateway 7.8
# rischi, 2023-02-17

from datetime import datetime
from http.cookiejar import CookieJar
from pprint import pprint
from urllib import request
import json
import os
import signal
import ssl
import subprocess
import sys

command = "/opt/airlock/base/bin/airlock-elasticsearch-query -q 'log_id: WR-SG-SUMMARY' -f @timestamp mapping"

used_mappings = {}
process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
for line in iter(process.stdout.readline, b''):
	jline = json.loads(line)
	ts = jline['@timestamp']
	map = jline['mapping']
	if map not in used_mappings:
		used_mappings[map] = ts
	else:
		new = datetime.strptime(ts.split(".")[0], '%Y-%m-%dT%H:%M:%S')
		ext = datetime.strptime(used_mappings[map].split(".")[0], '%Y-%m-%dT%H:%M:%S')
		if new > ext:
			used_mappings[map] = ts


cmd = "/opt/airlock/base/bin/airlock-user-manager-tool -J -u airlock-configuration-cli -j | jq -r '.[].token'"
API_KEY = subprocess.check_output(cmd, shell=True).decode("utf-8").rstrip()
TARGET_GATEWAY = f'http://localhost:8080'
DEFAULT_HEADERS = {"Authorization": f'Bearer {API_KEY}'}

opener = request.build_opener(request.HTTPCookieProcessor(CookieJar()))

# ignore invalid SSL cert on the management interface
if (not os.environ.get('PYTHONHTTPSVERIFY', '') and
        getattr(ssl, '_create_unverified_context', None)):
    ssl._create_default_https_context = ssl._create_unverified_context

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

send_request("POST", "session/create")
register_cleanup_handler()
load_last_config()
mappings = get_all_mappings()
all_mapping_names=[]
for i in mappings:
	all_mapping_names.append(i['attributes']['name'])

all_mapping_names.sort()

for m in all_mapping_names:
	not_found = True
	for u in used_mappings:
		if m == u:
			print("{:<50}: last use {}".format(m, used_mappings[u]));
			not_found = False
			break
	if not_found:
		print("{:<50}: not found in logs".format(m));
