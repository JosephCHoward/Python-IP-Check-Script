# Python IP Check Script
This script was created as the capstone project for the Security Scripting course in my MS in Information Security program at Champlain College.

## Objective
Checking the reputation of IP addresses is a labor intensive activity. This script is designed to automate the process of extracting IP addresses from a PCAP file, checking their reputation against AbuseIPDB, and returning selected data.

The script is designed as a proof of concept script and not intended for actual use.

## Main Components
For full details, see the attached Word document. The main components of the script are as follows:
1. Capture network traffic and write it to a PCAP file.
2. Extract IP addresses from the PCAP file and append them to an existing file containing known malicious IP addresses.
3. Check the reputation of the IP addresses against AbuseIPDB using an API key contained in a separate file (not attached).
4. Extract selected fields from the JSON data returned by AbuseIPDB.
5. Sort IP addresses and associated data according to IP reputation.
6. Write the results to an output file.
