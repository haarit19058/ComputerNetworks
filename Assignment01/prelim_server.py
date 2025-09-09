import socket
import json
from datetime import datetime

with open("rules.json") as f:
    rules = json.load(f)["timestamp_rules"]["time_based_routing"]

ip_pool = [
    "192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4", "192.168.1.5",
    "192.168.1.6", "192.168.1.7", "192.168.1.8", "192.168.1.9", "192.168.1.10", 
    "192.168.1.11", "192.168.1.12", "192.168.1.13", "192.168.1.14", "192.168.1.15"
]

def parse_time(timestr):
    h, m = map(int, timestr.split(":"))
    return h * 60 + m

def get_ip(header):

    hh = int(header[0:2])
    mm = int(header[2:4])
    pkt_id = int(header[6:8])

    current_minutes = hh * 60 + mm

    for name, rule in rules.items():
        start, end = rule["time_range"].split("-")
        start_min = parse_time(start)
        end_min = parse_time(end)

        if start_min <= end_min:
            in_range = start_min <= current_minutes <= end_min
        else:  # overnight rule
            in_range = (current_minutes >= start_min) or (current_minutes <= end_min)

        if in_range:
            start_idx = rule["ip_pool_start"]
            return ip_pool[start_idx + (pkt_id % rule["hash_mod"])]

    return "0.0.0.0"


HOST = '127.0.0.1'
PORT = 5553

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((HOST, PORT))

print(f"Server running on {HOST}:{PORT}")

while True:
    data, addr = sock.recvfrom(4096)
    client_ip, client_port = addr
    print(f"Received {len(data)} bytes from {client_ip}:{client_port}")

    # Extract custom header (8 bytes)
    header = data[:8].decode(errors="ignore")

    selected_ip = get_ip(header)

    try:
        sock.sendto(selected_ip.encode(), addr)
    except Exception as e:
        sock.sendto(f"Error: {e}".encode(), addr)

    print(f"Header={header} → Selected IP={selected_ip}")
