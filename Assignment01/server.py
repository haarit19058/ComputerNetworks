import socket
import json
from datetime import datetime
import dpkt
import pandas as pd

# Load routing rules from JSON
with open("rules.json") as f:
    rules = json.load(f)["timestamp_rules"]["time_based_routing"]

# Define IP Pool
# These are backend IP addresses available for assignment.
# The rules decide which IPs from this pool are selected.
ip_pool = [
    "192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4", "192.168.1.5",
    "192.168.1.6", "192.168.1.7", "192.168.1.8", "192.168.1.9", "192.168.1.10",
    "192.168.1.11", "192.168.1.12", "192.168.1.13", "192.168.1.14", "192.168.1.15"
]

# Convert HH:MM → minutes since midnight
def parse_time(timestr):
    h, m = map(int, timestr.split(":"))
    return h * 60 + m


# Select IP based on timestamp header
def get_ip(header):
    """
    Extracts timestamp & packet ID from header, 
    applies rules, and chooses an IP from pool.
    """
    # First 2 bytes = Hour, next 2 bytes = Minute
    hh = int(header[0:2])
    mm = int(header[2:4])
    
    # Last 2 bytes of header = packet ID (for hashing)
    pkt_id = int(header[6:8])

    # Current time in minutes since midnight
    current_minutes = hh * 60 + mm

    # Iterate through all rules in rules.json
    for name, rule in rules.items():
        # Each rule has a time range, like "08:00-16:00"
        start, end = rule["time_range"].split("-")
        start_min = parse_time(start)
        end_min = parse_time(end)

        # Handle both normal ranges (e.g., 08:00-16:00)
        # and overnight ranges (e.g., 22:00-06:00)
        if start_min <= end_min:
            in_range = start_min <= current_minutes <= end_min
        else:  
            in_range = (current_minutes >= start_min) or (current_minutes <= end_min)

        # If current time falls in the range, select IP
        if in_range:
            start_idx = rule["ip_pool_start"]  # Start position in ip_pool
            # Distribute packet IDs across the pool using modulo
            return ip_pool[start_idx + (pkt_id % rule["hash_mod"])]

    # Fallback IP if no rules matched
    return "0.0.0.0"


# UDP Server Setup
HOST = '127.0.0.1'   # Localhost
PORT = 5553          # Listening port (same as client uses)

# Create a UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((HOST, PORT))

print(f"Server running on {HOST}:{PORT}")

# DataFrame for logging queries
# Columns:
# Timestamp (header), Client IP/Port, Domain Name, Selected Backend IP
df = pd.DataFrame(columns=["Timestamp", "Client_IP", "Client_Port", "Domain", "Selected_IP"])


# Main Server Loop
while True:
    # Wait for client data (blocking call)
    data, addr = sock.recvfrom(4096)
    client_ip, client_port = addr
    print(f"Received {len(data)} bytes from {client_ip}:{client_port}")

    # Step 1: Parse custom header (8 bytes)
    header = data[:8].decode(errors="ignore")
    selected_ip = get_ip(header)

    # Step 2: Parse DNS payload
    dns_payload = data[8:]            # Everything after header is DNS data
    dns = dpkt.dns.DNS(dns_payload)   # Parse DNS packet
    domain_name = dns.qd[0].name if dns.qd else "unknown"

    # Step 3: Log query in DataFrame
    timestamp = header
    df = pd.concat([
        df,
        pd.DataFrame([[timestamp, client_ip, client_port, domain_name, selected_ip]],
                     columns=df.columns)
    ], ignore_index=True)

    # Step 4: Send response back to client
    try:
        # Format: domain|selected_ip
        sock.sendto(f"{domain_name}|{selected_ip}".encode(), addr)
    except Exception as e:
        sock.sendto(f"Error: {e}".encode(), addr)

    # Debugging info for server logs
    print(f"Header={header} → Domain={domain_name} → Selected IP={selected_ip}")

    # Step 5: Persist log to CSV
    df.to_csv("dns_log.csv", index=False)
