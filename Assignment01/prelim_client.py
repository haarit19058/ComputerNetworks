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
from scapy.all import rdpcap, DNS
from datetime import datetime

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 5553

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Read PCAP and filter DNS queries
packets = rdpcap("7.pcap") ###
dns_packets = [pkt for pkt in packets if pkt.haslayer(DNS)]

for idx, pkt in enumerate(dns_packets):
    dns_payload = bytes(pkt[DNS])

    # Create custom header HHMMSS + ID (2 digits)
    now = datetime.now()
    header = f"{now.hour:02}{now.minute:02}{now.second:02}{idx:02}".encode()  # 8 bytes
    print(header)

    # Prepend custom header
    message = header + dns_payload

    # Send to server
    sock.sendto(message, (SERVER_HOST, SERVER_PORT))
    data, _ = sock.recvfrom(1024)
    print(f"DNS Response: {data.decode()}")
    # print(f"Sent DNS query {idx:02} with header {header.decode()}")
