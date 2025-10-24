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
                        domains.append(dns.qd[0].name)
            except Exception:
                continue

    latencies = []
    outputs = []
    success = 0
    tries = len(domains)

    for domain in domains:
        start = time.time()
        out = host.cmd(f'dig +time=2 +tries=1 +short {domain}')
        end = time.time()
        latency = end - start
        latencies.append(latency)
        out_stripped = out.strip()
        outputs.append(out_stripped)
        if out_stripped:
            success += 1
        time.sleep(0.1)

    avg_latency = sum(latencies) / len(latencies) if latencies else None
    total_bytes = sum(len(o) for o in outputs)
    avg_throughput = total_bytes / sum(latencies) if latencies else None
    num_fail = tries - success

    return {
        'hostname': hostname,
        'avg_lookup_latency_sec': avg_latency,
        'avg_throughput_bytes_per_sec': avg_throughput,
        'num_successful_queries': success,
        'num_failed_resolutions': num_fail
    }



def run():
    setLogLevel('info')
    topo = CustomTopo()
    net = Mininet(topo=topo, link=TCLink, controller=Controller)
    # Add NAT node to s1
    nat = net.addNAT(link='s1', ip='10.0.0.254/24')
    nat.configDefault()
    net.start()

    hosts = [ net.get(h) for h in ('h1','h2','h3','h4','dns') ]

    info('*** Setting nameserver\n')
    for h in hosts:
        h.cmd("echo 'nameserver 8.8.8.8' > /etc/resolv.conf")

    info('*** Internal connectivity test\n')
    net.pingAll()

    info('*** External Internet connectivity test\n')
    print( net.get('h2').cmd('ping -c4 8.8.8.8') )

    info('*** Measuring metrics ***\n\n')
    rs_h1 = measure_native(net,'h1','PCAP_1_H1.pcap')
    pprint.pprint(rs_h1)
    rs_h2 = measure_native(net,'h2','PCAP_2_H2.pcap')
    pprint.pprint(rs_h2)
    rs_h3 = measure_native(net,'h3','PCAP_3_H3.pcap')
    pprint.pprint(rs_h3)
    rs_h4 = measure_native(net,'h4','PCAP_4_H4.pcap')
    pprint.pprint(rs_h4)

    CLI(net)
    net.stop()

if __name__ == '__main__':
    run()
