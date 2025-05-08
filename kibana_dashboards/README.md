This directory contains Kibana dashboards for Airlock Gateway

The files are not part of the official Airlock product delivery and Ergon/Airlock does not provide support for it. Best effort support may be provided by the contributor of the script.

### Getting started
**Import dashboard and associated visualizations**

1. Open Log Viewer in the Airlock Gateway Configuration Center
1. Click the hamburger button in the upper left corner
1. Goto *Stack Management* - *Saved Objects*
1. Click *Import* and select the file to import
1. Click *Import*

**Open Dashboard**

1. Click the hamburger button in the upper left corner
1. Goto Dashboards - Denial of Service Analysis

**Filter for a specific virtual host**

Click the name of the virtual host in the first chart to filter the whole dashboard for it. Or use this query in the KQL query bar:

`vhost : "my.vhostname.ch"`

### How to interpret the dashboards

Compare a timeline before an active DDoS attack with a timeline under active DDoS attacks (e.g. 24h each). The dashboards help to define a baseline with the following features:
- [DoS Attack Prevention](https://docs.airlock.com/gateway/8.3/index/1583435032060.html) on mapping
- [Dynamic IP Blocking](https://docs.airlock.com/gateway/8.3/index/1571978527018.html) on mapping and globally
- [Geolocation filter](https://docs.airlock.com/gateway/8.3/index/1571978527012.html) globally
- [IP session limit](https://docs.airlock.com/gateway/8.3/index/1583435032082.html) globally

| Feature      | Dashboard |
| ----------- | ----------- |
| DoS Attack Prevention  | Top 10 IPs |
| DoS Attack Prevention | Top 10 mappings |
| Dynamic IP Blocking | Top 10 IPs |
| Dynamic IP Blocking | Top 10 mappings |
| IP session limit | Sessions created / destroyed |
| IP session limit | Average sessions per minute per IP created |
| Geolocation filter | Requests by country |
| Geolocation filter | Requests by countries by 10 minutes |

### Content
- **dos.ndjson** Dashboard to analyze DDOS attacks
  - Tested with:
    - Airlock Gateway 8.3.1 (Kibana 8.15.2)
