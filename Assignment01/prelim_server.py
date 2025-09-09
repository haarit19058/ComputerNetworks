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
import json

rules = {}
with open("rules.json") as f:
    rules = json.load(f)
rules = rules["timestamp_rules"]["time_based_routing"]

ip_pool = [
"192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4", "192.168.1.5",
"192.168.1.6", "192.168.1.7", "192.168.1.8", "192.168.1.9", "192.168.1.10", 
"192.168.1.11", "192.168.1.12", "192.168.1.13", "192.168.1.14", "192.168.1.15"
]

def parse_time(timestr):
    h, m = map(int, timestr.split(":"))
    return h * 60 + m

def get_ip(header):
    # rules = RULES["timestamp_rules"]["time_based_routing"]
    id = header[6:8]
    current_time_str = header[:6]
    current_minutes = parse_time(current_time_str)

    for name, rule in rules.items():
        start, end = rule["time_range"].split("-")
        start_min = parse_time(start)
        end_min = parse_time(end)

        if start_min <= end_min:  
            if start_min <= current_minutes <= end_min:
                start_idx = rule["ip_pool_start"]
                return ip_pool[start_idx + id % rule["hash_mod"]]
        else:  
            if current_minutes >= start_min  or current_minutes <= end_min:
                start_idx = rule["ip_pool_start"]
                return ip_pool[start_idx + id % rule["hash_mod"]]

    return -1

HOST = '127.0.0.1'
PORT = 5553

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((HOST, PORT))

print(f"Server running on {HOST}:{PORT}")



while True:
    data, addr = sock.recvfrom(4096)

    # Extract custom header
    header = data[:8].decode()

    selected_ip = get_ip(header)
    
    try:
        response = str(selected_ip)
        sock.sendto(response.encode(), addr)
    except Exception as e:
        response = f"Error: {e}"

    print(f"Resolved: {response}\n")
