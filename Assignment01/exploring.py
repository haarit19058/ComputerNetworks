import dpkt

def print_dns_packet(ts, buf):
    eth = dpkt.ethernet.Ethernet(buf)
    print("Ethernet:")
    print(f"  Src MAC: {eth.src.hex(':')}")
    print(f"  Dst MAC: {eth.dst.hex(':')}")
    if not isinstance(eth.data, dpkt.ip.IP):
        return

    ip = eth.data
    print("  IP:")
    print(f"    Src: {ip.src.hex('.')}")
    print(f"    Dst: {ip.dst.hex('.')}")
    print(f"    Protocol: {ip.p}")

    if not isinstance(ip.data, dpkt.udp.UDP):
        return

    udp = ip.data
    print("    UDP:")
    print(f"      Src Port: {udp.sport}")
    print(f"      Dst Port: {udp.dport}")

    # Check if it's DNS
    if udp.sport != 53 and udp.dport != 53:
        return

    try:
        dns = dpkt.dns.DNS(udp.data)
    except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
        return

    print("      DNS:")
    print(f"        Transaction ID: {dns.id}")
    print(f"        Flags: qr={dns.qr}, opcode={dns.opcode}, rcode={dns.rcode}")
    print(f"        Questions: {len(dns.qd)}")
    print(f"        Answers: {len(dns.an)}")

    # Questions
    for q in dns.qd:
        print(f"          Q: {q.name} (Type={q.type}, Class={q.cls})")

    # Answers
    for ans in dns.an:
        print(f"          A: {ans.name} → {ans.rdata}")

# -------- Main loop --------
with open("7.pcap", "rb") as f:
    pcap = dpkt.pcap.Reader(f)
    for i, (ts, buf) in enumerate(pcap):
        print(f"\nPacket #{i+1} @ {ts}")
        print_dns_packet(ts, buf)
