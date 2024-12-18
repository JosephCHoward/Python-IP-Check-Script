# Python IP Reputation Check Script
This script was created as the capstone project for the Security Scripting course in my MS in Information Security program at Champlain College.

The script is intended as a proof of concept and not for use in live environments.

## Objective
Checking the reputation of IP addresses is a labor intensive activity. This script is designed to automate the process of extracting IP addresses from a PCAP file, checking their reputation against AbuseIPDB, and returning selected data.

## Main Components
For full details, see the Script Design file. The main components of the script are as follows:
1. Capture network traffic and write it to a PCAP file.
2. Extract IP addresses from the PCAP file and append them to an existing file containing known malicious IP addresses.
3. Check the reputation of the IP addresses against AbuseIPDB using an API key contained in a separate file (not attached).
4. Extract selected fields from the JSON data returned by AbuseIPDB.
5. Sort IP addresses and associated data according to IP reputation.
6. Write the results to an output file.

![image](https://github.com/user-attachments/assets/116dabd8-c645-48ba-b12f-c7fc8ef7f8e8)
