import dns.message
import dns.query
import dns.flags
import time
import datetime
import logging
from dns.exception import DNSException, Timeout

ROOT_SERVERS = [
    "198.41.0.4",      # a.root-servers.net
    "199.9.14.201",    # b.root-servers.net
    "192.33.4.12",     # c.root-servers.net
    "199.7.91.13",     # d.root-servers.net
    "192.203.230.10",  # e.root-servers.net
]

count = 0

logs = []
def log_event(domain, mode, server_ip, step, response_type, rtt, total_time, cache_status):
    logs.append({
        "Timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Domain": domain,
        "Mode": mode,
        "Server_IP": server_ip,
        "Step": step,
        "Response": response_type,
        "RTT(s)": round(rtt, 4) if rtt else None,
        "Cache": cache_status
    })

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
    i = 0
    resolved = False
    while i < len(ROOT_SERVERS):
        ip_from_cache = ""
        find_name = str(target_name)
        next_dot = str(target_name).find('.')

        while not ip_from_cache and next_dot > -1:
            ip_from_cache = dns_cache.get(find_name)
            find_name = str(find_name)[next_dot+1:]
            next_dot = find_name.find('.')

        if ip_from_cache:
            ip_ = ip_from_cache
            logging.debug(f"--------Found target {find_name} in cache--------\n")

        else:
            ip_ = ROOT_SERVERS[i]
            logging.debug(f"--------Using root server {ip_}--------\n")

        try:
            response, resolved = lookup_recurse(target_name, qtype, ip_, resolved, dns_cache)

            if response.answer:
                return response
            elif response.authority and response.authority[0].rdtype == dns.rdatatype.SOA:
                # logging.debug("---------Got SOA authority-------")
                break
            else:
                i += 1
                print(i)
        except Timeout:
            # logging.debug("Timeout")
            i += 1
        except DNSException:
            # logging.debug("DNSException")
            i += 1                      
    return response

def lookup_recurse(target_name: dns.name.Name,
                   qtype: dns.rdata.Rdata,
                   ip_,
                   resolved,
                   dns_cache: dict) -> dns.message.Message:
    """
    This function uses a recursive resolver to find the relevant answer to the
    query,
    """
    global count
    count += 1
    outbound_query = dns.message.make_query(target_name, qtype)
            # Determine response type
    # if ip_ in ROOT_SERVERS:
    #     step_type = "Root"
    #     result_type = "Referral"
    # elif response.answer:
    #     step_type = "Authoritative"
    #     
    # elif response.additional:
    #     step_type = "Referral"
    #    
    # elif response.authority:
    #     step_type = "Authority"
    #     result_type = "SOA" if response.authority[0].rdtype == dns.rdatatype.SOA else "NS"
    # else:
    #     step_type = "Unknown"
    #     result_type = "Empty"
    result_type = ""
    try:
        start_time = time.time()
        response = dns.query.udp(outbound_query, ip_, 3)
        rtt = (time.time() - start_time) * 1000  # in milliseconds
        print(f"Query to {ip_} took {rtt} ms")
        if response.answer:
            # logging.debug("\n---------Got Answer-------\n")
            resolved = True             
            result_type = "Response" 
            return response, resolved
        elif response.additional:
            result_type = "Referral"
            if response.authority:
                update_cache(response, dns_cache)
            response, resolved = lookup_additional(response, target_name,
                                                   qtype, resolved, dns_cache)

        elif response.authority and not resolved:
            result_type = "Referral"
            response, resolved = lookup_authority(response, target_name,
                                                  qtype, resolved, dns_cache)
        log_event(str(target_name), "Recursive", ip_, "Lookup Recurse",
                    result_type, rtt, time.time() - start_time, "MISS")
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
                      dns_cache: dict):
    """
    Recursively lookup additional
    """
    rrsets = response.additional
    for rrset in rrsets:
        for rr_ in rrset:
            if rr_.rdtype == dns.rdatatype.A:
                response, resolved = lookup_recurse(target_name, qtype,
                                                    str(rr_), resolved, dns_cache)
            if resolved:
                break
        if resolved:
            break
    return response, resolved
    
def lookup_authority(response,
                     target_name: dns.name.Name,
                     qtype: dns.rdata.Rdata,
                     resolved,
                     dns_cache: dict):
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
                                                    ns_ip, resolved, dns_cache)
            elif rr_.rdtype == dns.rdatatype.SOA:
                resolved = True
                break
        if resolved:
            break

    return response, resolved


def main():
    domain_names = ["google.com","google.com","amazon.com","wikipedia.org","nonexistentdomain.xyz"]
    dns_cache = {}
    dns_cache['response_cache'] = {}
    for domain_name in domain_names:
        cache_result = dns_cache.get('response_cache').get(domain_name)
        if cache_result:
            logging.debug("Got response in cache")
            for ans in cache_result.answer:
                print(ans)
        else:
            target_name = dns.name.from_text(domain_name)
            qtype = dns.rdatatype.A
            print(target_name, qtype)
            response = lookup(target_name, qtype, dns_cache)
            print(f"Final answer for {domain_name}:")
            for ans in response.answer:
                print(ans)
            
            dns_cache['response_cache'][domain_name] = response

if __name__ == "__main__":
    main()


# cache = {}  # optional cache: {domain: response}
# logs = []   # store all log entries

# def update_cache(response: dns.message.Message):
#     """
#     Update cache with intermediate results
#     """
   

#     arecords = []
#     rrsets = response.additional
#     for rrset in rrsets:
#         for rr_ in rrset:
#             if rr_.rdtype == dns.rdatatype.A:
#                 arecords.append(str(rr_))
#                 cache[domain_name] = str(rr_)




# def make_query(domain, qtype="A", server_ip="8.8.8.8", timeout=3, rdflag=False):
#     """Send a UDP DNS query and return (response, rtt, error)."""
#     q = dns.message.make_query(domain, qtype, want_dnssec=False)
#     if rdflag:
#         q.flags |= dns.flags.RD
#     else:
#         q.flags &= ~dns.flags.RD
#     start = time.monotonic()                       ns_ip = str(ns_arecords.answer[0][0])
                    # else:
                    #     continue
#     try:
#         response = dns.query.udp(q, server_ip, timeout=timeout)
#         rtt = time.monotonic() - start
#         return response, rtt, None
#     except Exception as e:
#         return None, None, str(e)


# def iterative_resolve(domain, qtype="A", start_time=None, step="Root"):
#     """Perform iterative DNS resolution with detailed logging."""
#     global cache
    # if start_time is None:
    #     start_time = time.monotonic()

#     # Cache check
#     if domain in cache:
        # total_time = time.monotonic() - start_time
#         log_event(domain, "Iterative", "-", "Cache", "Cache HIT", 0, total_time, "HIT")
#         return cache[domain]

#     current_servers = ROOT_SERVERS
#     tried = set()

#     while True:
#         for server in current_servers:
#             if server in tried:
#                 continue
#             tried.add(server)

#             response, rtt, err = make_query(domain, qtype, server, rdflag=False)
#             total_time = time.monotonic() - start_time

#             if err:
#                 log_event(domain, "Iterative", server, step, f"Error: {err}", rtt, total_time, "MISS")
#                 continue

#             # Case 1: Got final answer
#             if len(response.answer) > 0:
#                 log_event(domain, "Iterative", server, step, "Answer", rtt, total_time, "MISS")
#                 cache[domain] = response  # store in cache
#                 return response

#             # Case 2: Referral with IPs
#             elif len(response.additional) > 0:
#                 next_servers = []
#                 if response.authority:
#                     update_cache(response)
#                 rrsets = response.additional
#                 for rrset in rrsets:
#                     for rr_ in rrset:
#                         if rr_.rdtype == dns.rdatatype.A:
#                             next_servers.append(str(rr_))
#                 log_event(domain, "Iterative", server, step, "Referral (Additional)", rtt, total_time, "MISS")
#                 if next_servers:
#                     step = "TLD" if step == "Root" else "Authoritative"
#                     current_servers = next_servers
#                     break

#             # Case 3: Referral with NS names only
#             # elif len(response.authority) > 0:
#             #     ns_names = []
#             #     for auth in response.authority:
#             #         if auth.rdtype == dns.rdatatype.NS:
#             #             ns_names.extend([ns.to_text() for ns in auth.items])
#             #     log_event(domain, "Iterative", server, step, "Referral (Authority)", rtt, total_time, "MISS")
#             #     if ns_names:
#             #         # Resolve first NS name
#             #         ns_ip_resp = iterative_resolve(ns_names[0], "A", start_time, step="NS Lookup")
#             #         if ns_ip_resp and len(ns_ip_resp.answer) > 0:
#             #             for ans in ns_ip_resp.answer:
#             #                 if ans.rdtype == dns.rdatatype.A:
#             #                     current_servers = [ans.items[0].address]
#             #                     break
#             #         break

#         else:
#             return None


# def print_logs():
#     print("\n\n=== DNS Resolution Log ===")
#     for entry in logs:
#         print(" | ".join(f"{k}: {v}" for k, v in entry.items()))


# if __name__ == "__main__":
#     result = iterative_resolve("google.com")
#     print_logs()
#     if result:
#         print("\n--- FINAL ANSWER ---")
#         for ans in result.answer:
#             print(ans)
#     result = iterative_resolve("yahoo.com")
#     print_logs()
#     if result:
#         print("\n--- FINAL ANSWER ---")
#         for ans in result.answer:
#             print(ans)