#!/usr/bin/env python3
import socket
import dpkt
from datetime import datetime
from time import sleep, time
import argparse
import json

SERVER_HOST = "10.0.0.5"
SERVER_PORT = 5553
SOCKET_TIMEOUT = 2.5
INTER_PACKET_SLEEP = 0.1
RECV_BUF_SIZE = 4096

def resolve(filename, server_host=SERVER_HOST, server_port=SERVER_PORT):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    with open(filename, "rb") as f:
        # Read the pcap file using dpkt
        pcap = dpkt.pcap.Reader(f)

        dns_packets = []
        for ts, buf in pcap:
            try:
                # Parse the Ethernet frame
                eth = dpkt.ethernet.Ethernet(buf)

                # Check if it's an IP packet
                if not isinstance(eth.data, dpkt.ip.IP):
                    continue
                ip = eth.data
                if not isinstance(ip.data, dpkt.udp.UDP):
                    continue

                # Extract UDP packet
                udp = ip.data

                # Check if it's DNS (port 53) and parse
                if udp.sport == 53 or udp.dport == 53:
                    dns = dpkt.dns.DNS(udp.data)
                    if dns.qr == dpkt.dns.DNS_Q:  
                        dns_packets.append(dns)
            except Exception:
                continue

    for idx, dns in enumerate(dns_packets):
        # Raw DNS payload
        dns_payload = bytes(dns)

        # Custom header HHMMSS + ID
        now = datetime.now()
        header = f"{now.hour:02}{now.minute:02}{now.second:02}{idx:02}".encode()  # 8 bytes

        # Prepend custom header
        message = header + dns_payload
        sock.sendto(message, (server_host, server_port))
        sleep(0.5)



def main():
    parser = argparse.ArgumentParser(description="Replay DNS packets from pcap to UDP server and measure responses")
    parser.add_argument("--pcap", required=True, help="PCAP filename to read DNS queries from")
    parser.add_argument("--hostname", required=True, help="Output filename to write results (kept name 'hostname' for compatibility)")
    parser.add_argument("--server-host", default=SERVER_HOST, help="Server IP to send DNS payloads to")
    parser.add_argument("--server-port", type=int, default=SERVER_PORT, help="Server UDP port")
    args = parser.parse_args()

    resolve(args.pcap, server_host=args.server_host, server_port=args.server_port)


if __name__ == "__main__":
    main()
