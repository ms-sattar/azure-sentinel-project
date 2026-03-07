## Azure Sentinel Honeypot Home Lab

A cloud-based honeypot environment built in Microsoft Azure to capture and analyze real-world cyberattack attempts. The lab collects authentication logs from an exposed virtual machine and visualizes attacker activity using Microsoft Sentinel.

## Project Overview

This project demonstrates how Security Information and Event Management (SIEM) systems can be used to monitor, detect, and analyze malicious activity targeting cloud infrastructure.An intentionally exposed virtual machine was deployed to the internet to attract automated brute-force login attempts. Security logs were collected and analyzed to identify attacker patterns and geographic sources.

## Technologies Used

Microsoft Azure – Cloud infrastructure
Microsoft Sentinel – SIEM monitoring and threat detection
Azure Log Analytics – Centralized log collection and analysis
Windows Event Logs – Authentication and security event tracking
KQL (Kusto Query Language) – Log querying and analysis

## Lab Architecture

The honeypot environment consists of:
Azure Virtual Machine acting as the honeypot
<img width="1010" height="1035" alt="image" src="https://github.com/user-attachments/assets/e4e07eed-7819-44b8-91f2-f23074b6b4c3" />

Network Security Group allowing inbound RDP traffic
<img width="975" height="1214" alt="image" src="https://github.com/user-attachments/assets/9c01a476-ca9c-48e0-8c8f-a30c8ccfbbd8" />

Log Analytics Workspace collecting system logs
<img width="942" height="464" alt="image" src="https://github.com/user-attachments/assets/fcc83c16-e5c8-4829-b491-b8156e8916da" />

Sentinel SIEM analyzing security events
<img width="942" height="464" alt="image" src="https://github.com/user-attachments/assets/8f98eab9-83b3-4b5d-9787-a5c6a79e1b51" />

## Attack Visualization

<img width="975" height="472" alt="image" src="https://github.com/user-attachments/assets/822ec17a-92ab-4d73-af64-e0742879d497" />

## Log Query
FAILED_RDP_WITH_GEO_CL 
| extend username = extract(@"username:([^,]+)", 1, RawData),
         timestamp = extract(@"timestamp:([^,]+)", 1, RawData),
         latitude = extract(@"latitude:([^,]+)", 1, RawData),
         longitude = extract(@"longitude:([^,]+)", 1, RawData),
         sourcehost = extract(@"sourcehost:([^,]+)", 1, RawData),
         state = extract(@"state:([^,]+)", 1, RawData),
         label = extract(@"label:([^,]+)", 1, RawData),
         destination = extract(@"destinationhost:([^,]+)", 1, RawData),
         country = extract(@"country:([^,]+)", 1, RawData)
| where destination != "samplehost"
| where sourcehost != ""
| summarize event_count=count() by timestamp, label, country, state, sourcehost, username, destination, longitude, latitude

## Key Learnings

Implemented a cloud honeypot to observe real attack behavior
Learned how SIEM platforms correlate and analyze security logs
Practiced log analysis using Kusto Query Language (KQL)
Visualized cyberattack patterns using Sentinel dashboards

## Project Report
Full documentation of the lab setup and analysis is included in the project report.


