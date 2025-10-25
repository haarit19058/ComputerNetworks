import dns.message
import dns.query
import dns.flags
import time

# Start from a root server
ROOT_SERVERS = [
    "198.41.0.4",      # a.root-servers.net
    "199.9.14.201",    # b.root-servers.net
    "192.33.4.12",     # c.root-servers.net
    "199.7.91.13",     # d.root-servers.net
    "192.203.230.10",  # e.root-servers.net
]

def make_query(domain, qtype="A", server_ip="8.8.8.8", timeout=3, rdflag=False):
    """Send a DNS query and return (response, rtt, error)."""
    q = dns.message.make_query(domain, qtype, want_dnssec=False)
    if rdflag:
        q.flags |= dns.flags.RD
    else:
        q.flags &= ~dns.flags.RD
    start = time.monotonic()
    try:
        response = dns.query.udp(q, server_ip, timeout=timeout)
        rtt = time.monotonic() - start
        return response, rtt, None
    except Exception as e:
        return None, None, str(e)

def iterative_resolve(domain, qtype="A"):
    """Perform full iterative resolution from root → TLD → authoritative."""
    current_servers = ROOT_SERVERS
    tried = set()

    print(f"\n=== Iterative resolution for {domain} ===")

    while True:
        for server in current_servers:
            if server in tried:
                continue
            tried.add(server)
            print(f"\n→ Querying {server} for {domain} ({qtype})")
            response, rtt, err = make_query(domain, qtype, server, rdflag=False)
            if err:
                print(f"  [!] Error contacting {server}: {err}")
                continue

            # ✅ Case 1: Got an answer
            if len(response.answer) > 0:
                print("\n--- FINAL ANSWER ---")
                for ans in response.answer:
                    print(ans)
                return response

            # 🏢 Case 2: Referral — look at AUTHORITY and ADDITIONAL
            elif len(response.additional) > 0:
                next_servers = []
                rrsets = response.additional
                for rrset in rrsets:
                    for rr_ in rrset:
                        if rr_.rdtype == dns.rdatatype.A:
                            next_servers.append(str(rr_))
                if next_servers:
                    print(f"  ↳ Got {len(next_servers)} next-hop servers from ADDITIONAL")
                    current_servers = next_servers
                    break  # move to next iteration

            # 🧭 Case 3: Authority without IPs (need to resolve NS)
            elif len(response.authority) > 0:
                ns_names = []
                for auth in response.authority:
                    if auth.rdtype == dns.rdatatype.NS:
                        ns_names.extend([ns.to_text() for ns in auth.items])
                if ns_names:
                    print(f"  ↳ Need to resolve NS names: {ns_names[0]}")
                    # Resolve one NS name using recursion (temporary)
                    ns_ip_resp = iterative_resolve(ns_names[0], "A")
                    if ns_ip_resp and len(ns_ip_resp.answer) > 0:
                        for ans in ns_ip_resp.answer:
                            if ans.rdtype == dns.rdatatype.A:
                                current_servers = [ans.items[0].address]
                                break
                    break
        else:
            print("[x] No more servers to try.")
            return None

# Run test
if __name__ == "__main__":
    iterative_resolve("google.com")