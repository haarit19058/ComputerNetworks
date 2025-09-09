# import socket
# import dns.resolver  # pip install dnspython

# # Server configuration
# HOST = '127.0.0.1'
# PORT = 1235  # Custom port to avoid using system DNS port 53

# sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# sock.bind((HOST, PORT))

# print(f"DNS server running on {HOST}:{PORT}")

# while True:
#     data, addr = sock.recvfrom(1024)
#     domain = data.decode().strip()
#     print(f"Received query for: {domain} from {addr}")

#     try:
#         answers = dns.resolver.resolve(domain, 'A')
#         response = ', '.join([str(r) for r in answers])
#     except Exception as e:
#         response = f"Error: {e}"

#     sock.sendto(response.encode(), addr)



import socket
import dns.resolver  # pip install dnspython
from scapy.all import DNS

HOST = '127.0.0.1'
PORT = 5553

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((HOST, PORT))

print(f"Server running on {HOST}:{PORT}")

while True:
    data, addr = sock.recvfrom(4096)

    # Extract custom header
    header = data[:8].decode()
    dns_payload = data[8:]  # Original DNS packet
    print(f"Received header: {header} from {addr}")

    # Parse DNS packet using Scapy
    dns_pkt = DNS(dns_payload)
    query_name = dns_pkt.qd.qname.decode() if dns_pkt.qd else "N/A"
    print(f"DNS query: {query_name}")

    # Optional: resolve using dnspython
    try:
        answers = dns.resolver.resolve(query_name, 'A')
        response = ', '.join([str(r) for r in answers])
    except Exception as e:
        response = f"Error: {e}"

    print(f"Resolved: {response}\n")
