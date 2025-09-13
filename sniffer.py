#!/usr/bin/env python3
"""
CodeAlpha Internship - Cyber Security Task 1
--------------------------------------------
Aligned & Detailed Network Sniffer

This script captures and analyzes network traffic packets in real-time.
It displays packets in a clean aligned landscape format:
Source IP        → Destination IP   | Protocol | Length | TTL | Payload

Author: Premathas Vibeeshan
Internship: CodeAlpha Cyber Security
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP
import logging
import signal
import sys
from colorama import Fore, Style, init

# Initialize colorama for colored console output
init(autoreset=True)

# Configure logging
logging.basicConfig(
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.INFO
)

# Print header row once
print(
    f"{Fore.GREEN}{'Source IP'.ljust(18)} → {'Destination IP'.ljust(18)} | "
    f"{'Protocol'.ljust(8)} | {'Len'.ljust(6)} | {'TTL'.ljust(4)} | Payload{Style.RESET_ALL}"
)
print("-" * 90)

def packet_callback(packet):
    """
    Callback function to process each captured packet.
    Displays details in aligned landscape format.
    """
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        ttl = packet[IP].ttl
        length = len(packet)

        # Identify protocol + color
        if proto == 6 and packet.haslayer(TCP):
            protocol = Fore.CYAN + "TCP" + Style.RESET_ALL
        elif proto == 17 and packet.haslayer(UDP):
            protocol = Fore.MAGENTA + "UDP" + Style.RESET_ALL
        elif proto == 1 and packet.haslayer(ICMP):
            protocol = Fore.YELLOW + "ICMP" + Style.RESET_ALL
        else:
            protocol = Fore.WHITE + f"O({proto})" + Style.RESET_ALL

        # Try to get payload (first 40 bytes only)
        payload = ""
        try:
            if packet.haslayer(TCP) or packet.haslayer(UDP):
                raw_payload = bytes(packet[TCP if packet.haslayer(TCP) else UDP].payload)[:40]
                if raw_payload:
                    payload = raw_payload.decode(errors="ignore")
        except Exception:
            payload = "N/A"

        # Print aligned line
        print(
            f"{Fore.BLUE}{src_ip.ljust(18)}{Style.RESET_ALL} → "
            f"{Fore.RED}{dst_ip.ljust(18)}{Style.RESET_ALL} | "
            f"{protocol.ljust(8)} | "
            f"{str(length).ljust(6)} | "
            f"{str(ttl).ljust(4)} | "
            f"{payload if payload else 'None'}"
        )

def signal_handler(sig, frame):
    """Graceful exit on CTRL+C"""
    logging.info(Fore.RED + "Stopping Network Sniffer... Exiting." + Style.RESET_ALL)
    sys.exit(0)

def main():
    """Main function to start packet sniffing"""
    logging.info(Fore.GREEN + "Starting Aligned Network Sniffer... Press CTRL+C to stop." + Style.RESET_ALL)
    signal.signal(signal.SIGINT, signal_handler)
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    main()

