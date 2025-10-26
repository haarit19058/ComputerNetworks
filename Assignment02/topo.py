#!/usr/bin/env python3
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.node import Controller
import csv, re, itertools, time

class CustomTopo(Topo):
    def build(self):
        # Hosts
        h1 = self.addHost('h1', ip='10.0.0.1/24')
        h2 = self.addHost('h2', ip='10.0.0.2/24')
        h3 = self.addHost('h3', ip='10.0.0.3/24')
        h4 = self.addHost('h4', ip='10.0.0.4/24')
        dns = self.addHost('dns', ip='10.0.0.5/24')

        # Switches
        s1, s2, s3, s4 = [self.addSwitch(f's{i}') for i in range(1,5)]

        # Host-switch links
        self.addLink(h1, s1, bw=100, delay='2ms')
        self.addLink(h2, s2, bw=100, delay='2ms')
        self.addLink(h3, s3, bw=100, delay='2ms')
        self.addLink(h4, s4, bw=100, delay='2ms')

        # Switch-switch backbone
        self.addLink(s1, s2, bw=100, delay='5ms')
        self.addLink(s2, s3, bw=100, delay='8ms')
        self.addLink(s3, s4, bw=100, delay='10ms')

        # DNS node
        self.addLink(dns, s2, bw=100, delay='1ms')


def measure_pair(h1, h2):
    """Measure RTT (ping) and bandwidth (iperf) between two hosts"""

    # RTT test
    ping_output = h1.cmd(f'ping -c 5 {h2.IP()}')
    avg_rtt = None

    # Example out: "rtt min/avg/max/mdev = 22.095/27.828/49.580/10.884 ms"
    # Extract average RTT from ping output
    m = re.search(r'rtt min/avg/max/mdev = [\d\.]+/([\d\.]+)/', ping_output)

    if m:
        avg_rtt = float(m.group(1))
    else:
        times = re.findall(r'time=([\d\.]+) ms', ping_output)
        if times:
            avg_rtt = sum(map(float, times)) / len(times)

    # Bandwidth test (iperf TCP)
    h2.cmd('pkill -9 iperf')   # clean old iperf
    h2.cmd('iperf -s &')       # start server
    time.sleep(0.5)

    # Run iperf client
    iperf_out = h1.cmd(f'iperf -c {h2.IP()} -t 5')
    
    # Example out: "10.0000-6.3912 sec  71.6 MBytes  94.0 Mbits/sec"
    # Extract bandwidth from iperf output
    m2 = re.search(r'([\d\.]+)\s+Mbits/sec', iperf_out)

    bw_mbps = None
    if m2:
        bw_mbps = float(m2.group(1))
    elif 'bits/sec' in iperf_out:
        # fallback if it’s in Kbits/sec
        m3 = re.search(r'([\d\.]+)\s+Kbits/sec', iperf_out)
        if m3:
            bw_mbps = float(m3.group(1)) / 1000

    return avg_rtt, bw_mbps


def main():
    # Logging information
    setLogLevel('info')

    # Create network
    topo = CustomTopo()
    net = Mininet(topo=topo, link=TCLink, controller=Controller)

    # Add NAT for external connectivity
    nat = net.addNAT(link='dns', ip='10.0.0.254/24')
    nat.configDefault()

    # Starting network
    net.start()

    info('*** Running pingall test\n')
    net.pingAll()

    # Get hosts
    hosts = [net.get(h) for h in ('h1','h2','h3','h4','dns')]
    print(hosts)
    
    req_h = hosts[0]  # Host from which to run tests
    # Populate /etc/hosts for name resolution among hosts
    for host in hosts:
        req_h.cmd(f'echo "{host.IP()} {host.name}" >> /etc/hosts')

    results = []
    # print("*** Measuring RTT and Bandwidth between all host pairs\n")

    # # Iterate over all unique host pairs to identify measured RTT and Bandwidth
    # for h1, h2 in itertools.combinations(hosts, 2):
    #     print(f"\n>>> Testing {h1.name} <-> {h2.name}")
    #     avg_rtt, bw_mbps = measure_pair(h1, h2)
    #     results.append({
    #         'Host_Pair': f'{h1.name}-{h2.name}',
    #         'Avg_RTT_ms': round(avg_rtt, 3) if avg_rtt else None,
    #         'Bandwidth_Mbps': round(bw_mbps, 3) if bw_mbps else None
    #     })
    #     print(f"RTT = {avg_rtt:.2f} ms, Bandwidth = {bw_mbps:.2f} Mbps")

    # # Write to CSV
    # csv_filename = 'network_metrics.csv'
    # with open(csv_filename, 'w', newline='') as f:
    #     writer = csv.DictWriter(f, fieldnames=['Host_Pair', 'Avg_RTT_ms', 'Bandwidth_Mbps'])
    #     writer.writeheader()
    #     writer.writerows(results)
    # print(f"\nResults saved to {csv_filename}")

    # Launch CLI
    info('*** Launching CLI (type exit to quit)\n')
    CLI(net)
    net.stop()


if __name__ == '__main__':
    main()