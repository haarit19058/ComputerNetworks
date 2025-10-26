#!/usr/bin/env python3
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.node import Controller
import dpkt
import pprint
import time
import re

class CustomTopo( Topo ):
    def build( self ):
        h1 = self.addHost('h1', ip='10.0.0.1/24')
        h2 = self.addHost('h2', ip='10.0.0.2/24')
        h3 = self.addHost('h3', ip='10.0.0.3/24')
        h4 = self.addHost('h4', ip='10.0.0.4/24')
        dns = self.addHost('dns', ip='10.0.0.5/24')

        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')

        self.addLink(h1, s1, bw=100, delay='2ms')
        self.addLink(h2, s2, bw=100, delay='2ms')
        self.addLink(h3, s3, bw=100, delay='2ms')
        self.addLink(h4, s4, bw=100, delay='2ms')
        self.addLink(dns, s2, bw=100, delay='1ms')

        self.addLink(s1, s2, bw=100, delay='5ms')
        self.addLink(s2, s3, bw=100, delay='8ms')
        self.addLink(s3, s4, bw=100, delay='10ms')


 

def measure_native(net, hostname, filename):
    host = net.get(hostname)
    domains = []

    # Open the given pcap (packet capture) file in binary read mode
    with open(filename, "rb") as f:
        # Create a pcap reader object to read packets one by one
        pcap = dpkt.pcap.Reader(f)

        # Iterate through each packet in the pcap file
        for ts, buf in pcap:
            try:
                # Parse the raw packet buffer as an Ethernet frame
                eth = dpkt.ethernet.Ethernet(buf)

                # Skip if the Ethernet frame does not contain an IP packet
                if not isinstance(eth.data, dpkt.ip.IP):
                    continue

                # Extract the IP packet from the Ethernet frame
                ip = eth.data

                # Skip if the IP packet does not contain a UDP segment
                if not isinstance(ip.data, dpkt.udp.UDP):
                    continue

                # Extract the UDP segment from the IP packet
                udp = ip.data

                # Check if the UDP packet is DNS traffic (port 53)
                if udp.sport == 53 or udp.dport == 53:
                    # Parse the UDP payload as a DNS message
                    dns = dpkt.dns.DNS(udp.data)

                    # Check if this is a DNS *query* (qr = 0) and has at least one question
                    if dns.qr == dpkt.dns.DNS_Q and dns.qd:
                        # Extract the domain name from the first DNS query
                        domains.append(dns.qd[0].name)

            # Ignore any malformed packets or parsing errors
            except Exception:
                continue


    latencies = []
    throughputs = []
    success = 0
    failure = 0

    for domain in domains:
        start = time.time()
        out = host.cmd(f'dig +time=2 +tries=1 {domain}')
        end = time.time()
        total_latency = end - start  # fallback if no "Query time" found

        # Parse values using regex
        query_time_match = re.search(r"Query time:\s*(\d+)\s*msec", out)
        status_match = re.search(r"status:\s*(\w+)", out)
        size_match = re.search(r"MSG SIZE\s+rcvd:\s*(\d+)", out)

        # Default values
        latency = (int(query_time_match.group(1)) / 1000.0) if query_time_match else total_latency
        msg_size = int(size_match.group(1)) if size_match else 0
        status = status_match.group(1) if status_match else "UNKNOWN"

        latencies.append(latency)
        if status == "NOERROR":
            success += 1
        else:
            failure += 1

        # Throughput per query (bytes / second)
        if latency > 0:
            throughputs.append(msg_size / latency)

        time.sleep(0.1)

    # Compute averages
    avg_latency = sum(latencies) / len(latencies) if latencies else 0
    avg_throughput = sum(throughputs) / len(throughputs) if throughputs else 0

    return {
        'hostname': hostname,
        'avg_lookup_latency_sec': avg_latency,
        'avg_throughput_bytes_per_sec': avg_throughput,
        'num_successful_queries': success,
        'num_failed_resolutions': failure
    }

def run():
    setLogLevel('info')
    topo = CustomTopo()
    net = Mininet(topo=topo, link=TCLink, controller=Controller)
    # Add NAT node to s1
    nat = net.addNAT(link='dns', ip='10.0.0.254/24')
    nat.configDefault()
    net.start()

    hosts = [ net.get(h) for h in ('h1','h2','h3','h4','dns') ]

    info('*** Setting nameserver\n')
    for h in hosts:
        h.cmd("echo 'nameserver 8.8.8.8' > /etc/resolv.conf")
        # h.cmd("echo 'nameserver 10.0.0.5' > /etc/resolv.conf")

    info('*** Internal connectivity test\n')
    net.pingAll()

    info('*** External Internet connectivity test\n')
    print( net.get('h2').cmd('ping -c4 8.8.8.8') )

    # info('*** Measuring metrics Q2 ***\n\n')
    # with open('default_measurements_1.txt', 'w') as f:

    #     rs_h1 = measure_native(net,'h1','PCAP_1_H1.pcap')
    #     pprint.pprint(rs_h1)
    #     for key, value in rs_h1.items():
    #         f.write(f'H1 {key}: {value}\n')
    #     info('\n')


    #     rs_h2 = measure_native(net,'h2','PCAP_2_H2.pcap')
    #     pprint.pprint(rs_h2)
    #     for key, value in rs_h2.items():
    #         f.write(f'H2 {key}: {value}\n')
    #     info('\n')


    #     rs_h3 = measure_native(net,'h3','PCAP_3_H3.pcap')
    #     pprint.pprint(rs_h3)
    #     for key, value in rs_h3.items():
    #         f.write(f'H3 {key}: {value}\n')
    #     info('\n')


    #     rs_h4 = measure_native(net,'h4','PCAP_4_H4.pcap')
    #     pprint.pprint(rs_h4)
    #     for key, value in rs_h4.items():
    #         f.write(f'H4 {key}: {value}\n')
    #     info('\n')

    info("*** measuring metrics q4 ***\n")
    dns = net.get('dns')
    dns.cmd('python3 server.py &')

    hosts = [ net.get(h) for h in ('h1','h2','h3','h4')]

    for h in hosts:
        info(f'*** Starting client on {h} ***\n')
        num = h.name[1]
        h.cmd(f'sudo python3 client.py --pcap PCAP_{num}_H{num}.pcap --hostname H{num}')
        time.sleep(10)


    CLI(net)
    net.stop()

if __name__ == '__main__':
    run()