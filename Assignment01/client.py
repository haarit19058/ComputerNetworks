import socket
import dpkt
from datetime import datetime
from time import sleep


SERVER_HOST = '127.0.0.1'
SERVER_PORT = 5553

'''
This line creates a socket object 
socket.AF_INET specifies that we are using IPv4 addresses
socket.SOCK_DGRAM specifies that we are using UDP protocol
'''
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


'''
Ethernet frames are at the data link layer (Layer 2) of the OSI model.
They encapsulate packets from the network layer (Layer 3), such as IP packets.
When we read a pcap file, we get raw Ethernet frames, which include:
- Ethernet header (source MAC, destination MAC, EtherType)
- UDP packet (source port, destination port, length, checksum)
- DNS payload (queries, responses, etc.)
'''
with open("7.pcap", "rb") as f:
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
    sock.sendto(message, (SERVER_HOST, SERVER_PORT))

    # Receive DNS response from server
    data, _ = sock.recvfrom(1024)

    # Parse response DNS
    dns_resp = dpkt.dns.DNS(data)

    if dns_resp.an:  # check if there is at least one answer
        answer = dns_resp.an[0]
        domain_name = answer.name.decode() if isinstance(answer.name, bytes) else answer.name
        domain_ip = socket.inet_ntoa(answer.rdata) if answer.type == dpkt.dns.DNS_A else "N/A"
    else:
        domain_name = dns_resp.qd[0].name.decode() if dns_resp.qd else "unknown"
        domain_ip = "no answer"

    print(f"Response for packet {idx}: Domain={domain_name} -> IP:{domain_ip}")

    sleep(2)  # Pause between packets