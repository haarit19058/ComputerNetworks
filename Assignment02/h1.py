import dpkt


# read pcap file and extract DNS query packets
def read_pcap(file_path):
    dns_packets = []
    with open(file_path, "rb") as f:
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
                    if dns.qr == dpkt.dns.DNS_Q:  # DNS query
                        dns_packets.append(dns)
            except Exception as e:
                continue
    return dns_packets  


