import socket
import json
from datetime import datetime
import dpkt
import pandas as pd
import dns.message
import dns.query
import dns.flags
import time
import datetime
import logging
from dns.exception import DNSException, Timeout
import pandas as pd


# Convert HH:MM → minutes since midnight
def parse_time(timestr):
    h, m = map(int, timestr.split(":"))
    return h * 60 + m


# UDP Server Setup
HOST = '10.0.0.5'   # Localhost
PORT = 5553          # Listening port (same as client uses)

# Create a UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((HOST, PORT))

# print(f"Server running on {HOST}:{PORT}")


ROOT_SERVERS = [
    "198.41.0.4",      # a.root-servers.net
    "199.9.14.201",    # b.root-servers.net
    "192.33.4.12",     # c.root-servers.net
]


count = 0
total_time = 0
logs = []
client_ip = ""
total_bytes = 0

filename = "dns_resolution_log_v2.csv"

df = pd.DataFrame(columns=[
    "Timestamp",'Client IP', "Domain", "Mode", "Server_IP", "Step",
    "Response type", "RTT(s)", "Cache Status", "Cumulative Time(ms)"
])

# with open(filename, "w") as f:
#     f.write("Timestamp,Client_IP,Domain,Mode,Server_IP,Step,Response type,RTT(s),Cache Status,Cumulative Time(ms)\n")

def log_event(domain, mode, server_ip, step, response_type, rtt, cache_status):
    global df
    global total_time

    with open(filename, "a") as f:
        f.write(f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')},{client_ip},{domain},{mode},{server_ip},{step},{response_type},{round(rtt, 4) if rtt else None},{cache_status},{round(total_time, 4)}\n")

    new_row = pd.DataFrame([{
        "Timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Client IP":client_ip,
        "Domain": domain,
        "Mode": mode,
        "Server_IP": server_ip,
        "Step": step,
        "Response type": response_type,
        "RTT(s)": round(rtt, 4) if rtt else None,
        "Cache Status": cache_status,
        "Cumulative Time(ms)": round(total_time, 4)
    }])
    df = pd.concat([df, new_row], ignore_index=True)

    df.to_csv("dns_resolution_log.csv", index=False)

def update_cache(response: dns.message.Message, dns_cache):
    """
    Update cache with intermediate results
    """
    domain_name = response.authority[0].to_text().split(" ")[0]

    arecords = []
    rrsets = response.additional
    for rrset in rrsets:
        for rr_ in rrset:
            if rr_.rdtype == dns.rdatatype.A:
                arecords.append(str(rr_))
                dns_cache[domain_name] = str(rr_)
    print(f"Updated cache with {domain_name} : {arecords}")

def lookup(target_name: dns.name.Name,
           qtype: dns.rdata.Rdata,
           dns_cache: dict) -> dns.message.Message:
    global total_time
    global count
    global total_bytes
    i = 0
    resolved = False

    cache_tries = 0
    while i < len(ROOT_SERVERS):
        ip_from_cache = ""
        find_name = str(target_name)
        next_dot = str(target_name).find('.')

        while not ip_from_cache and next_dot > -1:
            ip_from_cache = dns_cache.get(find_name)
            find_name = str(find_name)[next_dot+1:]
            next_dot = find_name.find('.')

        if ip_from_cache:
            total_bytes = 0
            total_time = 0
            ip_ = ip_from_cache
            step_type = "Authoritative"
            log_event(str(target_name), "Recursive", "-", "Cache", "Referral", 0, "HIT")
            logging.debug(f"--------Found target {find_name} in cache--------\n")
            cache_tries += 1
            if cache_tries > 1:
                dns_cache.pop(find_name, None)
                ip_ = ROOT_SERVERS[i]
                step_type = "Root"
                # continue

        else:
            ip_ = ROOT_SERVERS[i]
            step_type = "Root"
            logging.debug(f"--------Using root server {ip_}--------\n")

        try:
            response, resolved = lookup_recurse(target_name, qtype, ip_, resolved, dns_cache, step_type)

            if response.answer:
                return response
            elif response.authority and response.authority[0].rdtype == dns.rdatatype.SOA:
                # logging.debug("---------Got SOA authority-------")
                break
            else:
                i += 1
                # print(i)
        except Timeout:
            # logging.debug("Timeout")
            i += 1
        except DNSException:
            # logging.debug("DNSException")
            i += 1                      

    return response # failure

def lookup_recurse(target_name: dns.name.Name,
                   qtype: dns.rdata.Rdata,
                   ip_,
                   resolved,
                   dns_cache: dict, step_type) -> dns.message.Message:
    """
    This function uses a recursive resolver to find the relevant answer to the
    query,
    """
    global total_time
    global count
    global total_bytes
    outbound_query = dns.message.make_query(target_name, qtype)
    total_bytes += len(outbound_query.to_wire())

            # Determine response type

    next_step = "Authoritative"

    if step_type == "Root":
        next_step = "TLD"
    
    result_type = ""
    try:
        start = time.monotonic()
        response = dns.query.udp(outbound_query, ip_, 3)
        rtt = (time.monotonic() - start) * 1000.0
        count += 1
        total_time += rtt

        # print(f"Query to {ip_} took {rtt} ms")
        if response.answer:
            # logging.debug("\n---------Got Answer-------\n")
            resolved = True             
            result_type = "Response" 
            log_event(str(target_name), "Recursive", ip_ , step_type, "Response", rtt, "MISS")
            return response, resolved
        elif response.additional:
            result_type = "Referral"
            if response.authority:
                update_cache(response, dns_cache)
            log_event(str(target_name), "Recursive", ip_, step_type, result_type, rtt, "MISS")
            response, resolved = lookup_additional(response, target_name,
                                                   qtype, resolved, dns_cache, next_step)

        elif response.authority and not resolved:
            result_type = "Referral"
            log_event(str(target_name), "Recursive", ip_, step_type, result_type, rtt, "MISS")
            response, resolved = lookup_authority(response, target_name,
                                                  qtype, resolved, dns_cache, next_step)
        return response, resolved

    except Timeout:
        # logging.debug("Timeout")
        return dns.message.Message(), False
    except DNSException:
        # logging.debug("DNSException")
        return dns.message.Message(), False
    
def lookup_additional(response,
                      target_name: dns.name.Name,
                      qtype: dns.rdata.Rdata,
                      resolved,
                      dns_cache: dict, step_type) -> dns.message.Message:
    """
    Recursively lookup additional
    """
    rrsets = response.additional
    for rrset in rrsets:
        for rr_ in rrset:
            if rr_.rdtype == dns.rdatatype.A:
                response, resolved = lookup_recurse(target_name, qtype,
                                                    str(rr_), resolved, dns_cache, step_type)
            if resolved:
                break
        if resolved:
            break
    return response, resolved
    
def lookup_authority(response,
                     target_name: dns.name.Name,
                     qtype: dns.rdata.Rdata,
                     resolved,
                     dns_cache: dict,step_type):
    """3
    Recursively lookup authority
    """                  
    rrsets = response.authority
    ns_ip = ""
    for rrset in rrsets:
        for rr_ in rrset:
            if rr_.rdtype == dns.rdatatype.NS:
                ns_ip = dns_cache.get(str(rr_))
                if not ns_ip:
                    ns_arecords = lookup(str(rr_), dns.rdatatype.A, dns_cache)
                    if ns_arecords.answer and len(ns_arecords.answer[0]) > 0:
                        ns_ip = str(ns_arecords.answer[0][0])
                    else:
                        continue
                    dns_cache[str(rr_)] = ns_ip

                response, resolved = lookup_recurse(target_name, qtype,
                                                    ns_ip, resolved, dns_cache,step_type)
            elif rr_.rdtype == dns.rdatatype.SOA:
                resolved = True
                break
        if resolved:
            break

    return response, resolved

# def print_logs():
    # print("\n\n=== DNS Resolution Log ===")
    # for entry in logs:
        # print(" | ".join(f"{k}: {v}" for k, v in entry.items()))



dns_cache = {}
dns_cache['response_cache'] = {}
failure = 0
success = 0

while True:
    # global total_time
    # global logs
    # Wait for client data
    data, addr = sock.recvfrom(4096)
    client_ip, client_port = addr
    # print(f"Received {len(data)} bytes from {client_ip}:{client_port}")

    # Step 1: Parse custom header (8 bytes)
    header = data[:8].decode(errors="ignore")
    # selected_ip = get_ip(header)  # custom function -> returns string like "1.2.3.4"

    # Step 2: Parse DNS payload
    dns_payload = data[8:]             # Everything after header is DNS data
    dns_req = dpkt.dns.DNS(dns_payload)

    domain_name = dns_req.qd[0].name if dns_req.qd else "unknown"

    cache_result = dns_cache.get('response_cache').get(domain_name)

    if cache_result:
        total_bytes = 0
        total_time = 0
        log_event(str(target_name), "Recursive", "-", "Cache", "Response", 0, "HIT")
        for ans in cache_result.answer:
            print(ans)
    else:
        # making target name and qtype objects
        target_name = dns.name.from_text(domain_name)
        qtype = dns.rdatatype.A
        # print(target_name, qtype)
        response = lookup(target_name, qtype, dns_cache)
        if not response.answer:
            log_event(str(target_name), "Recursive", "-", "N/A", "Failure", 0, "MISS")
            failure += 1
        
        
        success += 1
        # print(f"Final answer for {domain_name}:")
        for ans in response.answer:
            print(ans)
        dns_cache['response_cache'][domain_name] = response
    
    

    # print_logs()
    # print("Total resolution time:", total_time, "ms\n\n")
    total_bytes = 0
    total_time = 0
    logs = []
    # print("Total queries made:", count)

