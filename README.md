# Network Packet Analyzer

## Purpose
The purpose of this project is to implement a network packet analyzer using Python's `scapy` library. This tool captures and inspects data packets traversing a network interface, providing detailed information about source and destination IPs, ports, protocols (TCP, UDP, ICMP), and payload data.

## Description
This script utilizes `scapy` to sniff network packets and analyze their contents in real-time. It distinguishes between different protocols (TCP, UDP, ICMP) and extracts relevant information such as source and destination IP addresses, ports, and payload data. It serves as a powerful tool for network administrators and security analysts to monitor and troubleshoot network traffic.

## How It Works
1. **Packet Handling:**
   - The script uses `scapy.sniff` to capture packets on all available network interfaces.
   - For each packet captured, it checks the protocol type (IP, TCP, UDP, ICMP) and extracts relevant header fields and payload data.

2. **Output:**
   - For each packet:
     - Displays source and destination IP addresses.
     - Identifies protocol type (TCP, UDP, ICMP) and respective source/destination ports.
     - Prints the first 20 bytes of payload data if available.
   - Outputs are printed in real-time as packets are sniffed and analyzed.

## Example Usage
1. **Start Packet Analysis:**
   - Run the script to begin capturing and analyzing network packets.
   - It listens to all network traffic on the machine's interfaces.

2. **Packet Details:**
   - As packets are captured, the script displays detailed information:
     - Source and destination IP addresses.
     - Protocol type (TCP, UDP, ICMP) and associated ports.
     - Brief view of payload data for TCP, UDP, and ICMP packets.

3. **Real-time Monitoring:**
   - Continuously monitors network traffic and provides insights into communication patterns and data exchange.
   - Useful for troubleshooting network issues, identifying security threats, and analyzing protocol usage.

## Notes
- Ensure Python and the `scapy` library are installed to run the script.
- Use this tool responsibly and adhere to legal and ethical guidelines regarding network monitoring and packet capture.
