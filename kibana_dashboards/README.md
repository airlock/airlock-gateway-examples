This directory contains Kibana dashboards for Airlock Gateway

The files are not part of the official Airlock product delivery and Ergon/Airlock does not provide support for it. Best effort support may be provided by the contributor of the script.

**Import dashboard and associated visualizations**

1. Open Log Viewer in the Airlock Gateway Configuration Center
1. Click the hamburger button in the upper left corner
1. Goto *Stack Management* - *Saved Objects*
1. Click *Import* and select the file to import
1. Click *Import*

**Open Dashboard**

1. Click the hamburger button in the upper left corner
2. Goto Dashboards - Denial of Service Analysis

**Filter for specific Virtual Host**

Use this query in the KQL query bar:

`vhost : "my.vhostname.ch"`

### Content
- **dos.ndjson** Dashboard to analyze DDOS attacks
  - Tested with:
    - Airlock Gateway 8.3.1 (Kibana 8.15.2)
