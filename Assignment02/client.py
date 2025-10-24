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

def resolve_and_measure(filename, server_host=SERVER_HOST, server_port=SERVER_PORT):
    dns_packets = []
    with open(filename, "rb") as f:
        pcap = dpkt.pcap.Reader(f)
        for ts, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                if not isinstance(eth.data, dpkt.ip.IP):
                    continue
                ip = eth.data
                if not isinstance(ip.data, dpkt.udp.UDP):
                    continue
                udp = ip.data
                if udp.sport == 53 or udp.dport == 53:
                    dns = dpkt.dns.DNS(udp.data)
                    if dns.qr == dpkt.dns.DNS_Q and dns.qd:
                        dns_packets.append(dns)
            except Exception:
                continue

    latencies = []
    outputs = []
    success = 0
    tries = len(dns_packets)

    if tries == 0:
        return {
            "avg_lookup_latency_sec": None,
            "avg_throughput_bytes_per_sec": None,
            "num_successful_queries": 0,
            "num_failed_resolutions": 0,
        }

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(SOCKET_TIMEOUT)
        for idx, dns in enumerate(dns_packets):
            dns_payload = bytes(dns)
            now = datetime.now()
            header = f"{now.hour:02}{now.minute:02}{now.second:02}{idx:02}".encode()
            message = header + dns_payload

            try:
                start = time()
                sock.sendto(message, (server_host, server_port))
                data, _ = sock.recvfrom(RECV_BUF_SIZE)
                end = time()
                rtt = end - start
                latencies.append(rtt)
                outputs.append(data)

                try:
                    dns_resp = dpkt.dns.DNS(data)
                except Exception:
                    dns_resp = None

                if dns_resp and dns_resp.an:
                    answer = dns_resp.an[0]
                    if isinstance(answer.name, bytes):
                        domain_name = answer.name.decode(errors="ignore")
                    else:
                        domain_name = str(answer.name)

                    domain_ip = "N/A"
                    try:
                        if answer.type == dpkt.dns.DNS_A:
                            domain_ip = socket.inet_ntoa(answer.rdata)
                        elif answer.type == dpkt.dns.DNS_AAAA:
                            domain_ip = socket.inet_ntop(socket.AF_INET6, answer.rdata)
                        else:
                            domain_ip = str(answer.rdata)
                    except Exception:
                        domain_ip = "parse_error"

                    success += 1
                else:
                    domain_name = dns.qd[0].name if dns.qd else "unknown"
                    if isinstance(domain_name, bytes):
                        domain_name = domain_name.decode(errors="ignore")
                    domain_ip = "no_answer"

            except socket.timeout:
                latencies.append(SOCKET_TIMEOUT)
                outputs.append(b"")
            except Exception:
                latencies.append(SOCKET_TIMEOUT)
                outputs.append(b"")

            sleep(INTER_PACKET_SLEEP)

    avg_latency = sum(latencies) / len(latencies) if latencies else None
    total_bytes = sum(len(o) for o in outputs)
    sum_time = sum(latencies) if latencies else 0
    avg_throughput = (total_bytes / sum_time) if sum_time > 0 else None
    num_fail = tries - success

    return {
        "avg_lookup_latency_sec": avg_latency,
        "avg_throughput_bytes_per_sec": avg_throughput,
        "num_successful_queries": success,
        "num_failed_resolutions": num_fail,
    }

def main():
    parser = argparse.ArgumentParser(description="Replay DNS packets from pcap to UDP server and measure responses")
    parser.add_argument("--pcap", required=True, help="PCAP filename to read DNS queries from")
    parser.add_argument("--hostname", required=True, help="Output filename to write results (kept name 'hostname' for compatibility)")
    parser.add_argument("--server-host", default=SERVER_HOST, help="Server IP to send DNS payloads to")
    parser.add_argument("--server-port", type=int, default=SERVER_PORT, help="Server UDP port")
    args = parser.parse_args()

    result = resolve_and_measure(args.pcap, server_host=args.server_host, server_port=args.server_port)

    with open(args.hostname, "w") as outf:
        json.dump(result, outf, indent=2)

if __name__ == "__main__":
    main()
