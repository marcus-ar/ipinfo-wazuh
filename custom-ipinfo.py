#!/var/ossec/framework/python/bin/python3
## IPInfo API Integration
#
import sys
import os
from socket import socket, AF_UNIX, SOCK_DGRAM
from datetime import date, datetime, timedelta
import time
import requests
from requests.exceptions import ConnectionError
import json
import ipaddress
import hashlib
import re
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
socket_addr = '{0}/queue/sockets/queue'.format(pwd)
def send_event(msg, agent = None):
    if not agent or agent["id"] == "000":
        string = '1:ipinfo:{0}'.format(json.dumps(msg))
    else:
        string = '1:[{0}] ({1}) {2}->ipinfo:{3}'.format(agent["id"], agent["name"], agent["ip"] if "ip" in agent else "any", json.dumps(msg))
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(socket_addr)
    sock.send(string.encode())
    sock.close()
false = False
# Read configuration parameters
alert_file = open(sys.argv[1])
# Read the alert file
alert = json.loads(alert_file.read())
alert_file.close()
# New Alert Output if IPInfo Alert or Error calling the API
alert_output = {}
# IPInfo Server Base URL
ipinfo_base_url = "https://ipinfo.io/"
# IPInfo API AUTH KEY
ipinfo_api_auth_key = "<YOUR_TOKEN>"
event_source = alert["rule"]["id"][0]
try:
    src_ip = alert["data"]["srcip"]
    if ipaddress.ip_address(src_ip).is_global:
            wazuh_event_param = src_ip
    else:
        sys.exit()
except IndexError:
    sys.exit()
ipinfo_search_value = wazuh_event_param
ipinfo_search_url = ''.join([ipinfo_base_url, ipinfo_search_value,'?token=', ipinfo_api_auth_key])
try:
        ipinfo_api_response = requests.get(ipinfo_search_url, verify=False)
except ConnectionError:
        alert_output["ipinfo"] = {}
        alert_output["integration"] = "ipinfo"
        alert_output["ipinfo"]["error"] = 'Connection Error to IPInfo API'
        send_event(alert_output, alert["agent"])
else:
    ipinfo_api_response = ipinfo_api_response.json()
    # Generate Alert Output from IPInfo Response
    alert_output["ipinfo"] = {}
    alert_output["ipinfo"]["source"] = {}
    alert_output["ipinfo"]["ip"] = ipinfo_api_response["ip"]
    alert_output["ipinfo"]["hostname"] = ipinfo_api_response["hostname"]
    alert_output["ipinfo"]["city"] = ipinfo_api_response["city"]
    alert_output["ipinfo"]["region"] = ipinfo_api_response["region"]
    alert_output["ipinfo"]["country"] = ipinfo_api_response["country"]
    alert_output["ipinfo"]["loc"] = ipinfo_api_response["loc"]
    alert_output["ipinfo"]["org"] = ipinfo_api_response["org"]
    alert_output["ipinfo"]["postal"] = ipinfo_api_response["postal"]
    alert_output["ipinfo"]["timezone"] = ipinfo_api_response["timezone"]
    alert_output["ipinfo"]["source"]["description"] = alert["rule"]["description"]
    alert_output["ipinfo"]["source"]["alert"] = alert["id"]
    alert_output["integration"] = "ipinfo"
    send_event(alert_output, alert["agent"])


