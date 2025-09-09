# import socket

# # Server configuration
# SERVER_HOST = '127.0.0.1'
# SERVER_PORT = 1235

# sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# while True:
#     domain = input("Enter domain name: ").strip()
#     if not domain:
#         break

#     sock.sendto(domain.encode(), (SERVER_HOST, SERVER_PORT))
#     data, _ = sock.recvfrom(1024)
#     print(f"DNS Response: {data.decode()}")

import socket
import dpkt
from datetime import datetime

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 5553

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Open PCAP file
with open("7.pcap", "rb") as f:
    pcap = dpkt.pcap.Reader(f)

    dns_packets = []
    for ts, buf in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            if not isinstance(eth.data, dpkt.ip.IP):
                continue
            ip = eth.data
            if not isinstance(ip.data, dpkt.udp.UDP):
                continue
            udp = ip.data

            # Check if it's DNS (port 53) and parse
            if udp.sport == 53 or udp.dport == 53:
                dns = dpkt.dns.DNS(udp.data)
                if dns.qr == dpkt.dns.DNS_Q:  # Query
                    dns_packets.append(dns)
        except Exception:
            continue

# Send DNS packets to server
for idx, dns in enumerate(dns_packets):
    # Raw DNS payload
    dns_payload = bytes(dns)

    # Custom header HHMMSS + ID
    now = datetime.now()
    header = f"{now.hour:02}{now.minute:02}{now.second:02}{idx:02}".encode()  # 8 bytes

    # Prepend custom header
    message = header + dns_payload
    sock.sendto(message, (SERVER_HOST, SERVER_PORT))

    # Receive response
    data, _ = sock.recvfrom(1024)
    # Print query name(s) for debugging
    query_names = [q.name.decode() for q in dns.qd] if dns.qd else []
    print(f"Response for packet {idx}: Query={query_names} -> {data.decode()}")
