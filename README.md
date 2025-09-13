CodeAlpha – Basic Network Sniffer
--------------------------------------------------------------------------------------------------------------------------------------

This project is part of my CodeAlpha Cyber Security Internship (Task 1).
It is a Python-based network sniffer that captures and analyzes network traffic packets in real-time.

The tool helps understand how data flows across the network by displaying details such as:

Source IP → Destination IP

Protocol (TCP, UDP, ICMP, etc.)

Packet Length & TTL

Payload (first 40 bytes)


Features
--------------------------------------------------------------------------------------------------------------------------------------

✅ Real-time packet capture using Scapy
✅ Color-coded, aligned, and clean output (landscape style)
✅ Displays Source IP, Destination IP, Protocol, Length, TTL, Payload
✅ Graceful exit with CTRL+C
✅ Works on Linux/Ubuntu


Setup Instructions (Ubuntu)
--------------------------------------------------------------------------------------------------------------------------------------

1. Clone the Repository

              git clone https://github.com/premathasvibeeshan4/CodeAlpha_BasicNetworkSniffer/tree/main
              cd CodeAlpha_BasicNetworkSniffer

2. Create Virtual Environment (recommended)
              sudo apt update
              sudo apt install python3-venv -y

              python3 -m venv venv
              source venv/bin/activate

3. Install Requirements
              pip install scapy colorama


(or use system packages: sudo apt install python3-scapy python3-colorama -y)


Running the Sniffer
--------------------------------------------------------------------------------------------------------------------------------------

1. Run with root privileges to capture packets:

              sudo python3 sniffer.py

2. Sample Output

Source IP          → Destination IP    | Protocol | Len   | TTL  | Payload
------------------------------------------------------------------------------------------
212.219.147        → 192.168.8.103     | TCP      | 105   | 239  | "$]b6TǴ:nn
192.168.8.103      → 54.212.219.147    | TCP      | 66    | 64   | None
192.168.8.1        → 192.168.8.103     | ICMP     | 226   | 64   | None

3. Packet Explanation (Example)
212.219.147 → 192.168.8.103 | TCP | 105 | 239 | "$]b6TǴ:nn


212.219.147 → Remote host (internet)

192.168.8.103 → My local machine

TCP → Protocol used

105 → Packet length (bytes)

239 → Time-To-Live (hops before expiration)

Payload → Partial application data (text/binary)
