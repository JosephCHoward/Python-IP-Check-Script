# Joseph Howard
# Python Scripting Course
# June 25, 2024
# Final Project

import pyshark
import requests
import json
import os
import ipaddress

def start_packet_capture(interface, output_file, duration):
    try:
        print("Packet capture has begun.")
        capture = pyshark.LiveCapture(interface=interface, output_file=output_file)
        capture.sniff(timeout=duration)
        print("Packet capture complete.")
    except Exception as e:
        print(f"Error during packet capture: {e}")
        exit(1)

def is_valid_ip(ip):
    """
    Check if an IP address is valid and should be included in the output.
    Exclude private, broadcast, and the specific VM IP.
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        # Exclude private addresses, broadcast addresses, and the specific VM IP
        if ip_obj.is_private or ip_obj.is_multicast or ip_obj.is_unspecified or ip_obj.is_reserved or ip_obj.is_loopback or ip == '255.255.255.255' or ip == '192.168.159.128':
            return False
        return True
    except ValueError:
        return False

def read_existing_ips(file_path):
    """
    Read the existing IP addresses from the file.
    """
    try:
        with open(file_path, 'r') as f:
            existing_ips = {line.strip() for line in f if line.strip()}
        return existing_ips
    except FileNotFoundError:
        return set()
    except Exception as e:
        print(f"Error reading existing IP addresses from file: {e}")
        exit(1)

def extract_ips_from_capture(capture_file, output_file):
    try:
        print(f"Opening capture file: {capture_file}")
        capture = pyshark.FileCapture(capture_file)
        existing_ips = read_existing_ips(output_file)
        
        with open(output_file, 'a') as f:
            print(f"Appending IP addresses to file: {output_file}")
            for packet in capture:
                if 'IP' in packet:
                    ip_dst = packet.ip.dst
                    if is_valid_ip(ip_dst) and ip_dst not in existing_ips:
                        f.write(f"{ip_dst}\n")
                        existing_ips.add(ip_dst)
        print("Unique destination IP addresses extracted and appended to file.")
    except FileNotFoundError:
        print("The file does not exist or is inaccessible. The script has been terminated.")
        exit(1)
    except Exception as e:
        print(f"Error extracting IP addresses: {e}")
        exit(1)

def read_ips_from_file(file_path):
    try:
        with open(file_path, 'r') as f:
            ip_addresses = [line.strip() for line in f if line.strip()]
        return ip_addresses
    except Exception as e:
        print(f"Error reading IP addresses from file: {e}")
        exit(1)

def check_ip_with_abuseipdb(ip, api_key):
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
    headers = {
        'Accept': 'application/json',
        'Key': api_key
    }
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Network error while checking IP {ip}: {e}")
        exit(1)

def save_results(results, output_file):
    try:
        sorted_results = sorted(results, key=lambda x: x["data"]["abuseConfidenceScore"], reverse=True)
        header = "Results ranked in descending order according to AbuseIPDB score:\n"
        
        print(header)  # Print header to the screen
        with open(output_file, 'w') as f:
            f.write(header + "\n")
            for result in sorted_results:
                data = result["data"]
                result_text = (
                    f"IP Address = {data['ipAddress']}\n"
                    f"Country Code = {data.get('countryCode', 'N/A')}\n"
                    f"Domain = {data.get('domain', 'N/A')}\n"
                    f"ISP = {data.get('isp', 'N/A')}\n"
                    f"AbuseIPDB Abuse Confidence Score = {data.get('abuseConfidenceScore', 'N/A')}\n"
                    f"Number of Distinct Users Reporting IP Address = {data.get('numDistinctUsers', 'N/A')}\n"
                    f"Total Reports of IP Address = {data.get('totalReports', 'N/A')}\n"
                    f"Time of Latest Report = {data.get('lastReportedAt', 'N/A')}\n"
                    f"\n"
                )
                f.write(result_text)
                print(result_text)
        
        print("Results saved to file.")
    except Exception as e:
        print(f"Error saving results to file: {e}")
        exit(1)

def main():
    interface = 'eth0'
    pcap_file = '/home/kali/Documents/Project/packet_capture.pcap'
    ip_file = '/home/kali/Documents/Project/ip_addresses.txt'
    api_key_file = '/home/kali/Documents/Project/**************.txt'
    result_file = '/home/kali/Documents/Project/abuseipdb_reports.txt'
    duration = 30  # 30 seconds

    # Start packet capture
    start_packet_capture(interface, pcap_file, duration)

    # Extract IP addresses from pcap file
    extract_ips_from_capture(pcap_file, ip_file)

    # Read IP addresses from file
    ip_addresses = read_ips_from_file(ip_file)

    # Select the first 20 IP addresses
    ip_addresses = ip_addresses[:20]

    print("Checking the reputation of selected IP addresses against AbuseIPDB.")

    # Read API key from file
    try:
        with open(api_key_file, 'r') as f:
            api_key = f.read().strip()
    except Exception as e:
        print(f"Error reading API key from file: {e}")
        exit(1)

    # Check each IP address with AbuseIPDB
    results = []
    for ip in ip_addresses:
        result = check_ip_with_abuseipdb(ip, api_key)
        if result:
            results.append(result)

    # Save results to file and print to screen
    save_results(results, result_file)

if __name__ == "__main__":
    main()
