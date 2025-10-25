
DNS Query contains: (domain name, The DNS class (always IN (Internet)), Record type)

| Query Type | Meaning                   | Example Question            |
| ---------- | ------------------------- | --------------------------- |
| **A**      | IPv4 address              | `example.com. IN A`         |
| **AAAA**   | IPv6 address              | `example.com. IN AAAA`      |
| **MX**     | Mail server               | `example.com. IN MX`        |
| **NS**     | Nameserver                | `example.com. IN NS`        |
| **TXT**    | Text/verification records | `example.com. IN TXT`       |
| **CNAME**  | Canonical alias           | `www.example.com. IN CNAME` |
| **SOA**    | Start of Authority        | administrative info for a DNS zone.|

DNS response contains: (doamin name, TTL,The DNS class, Record type, answer)
DNS servers prove nonexistence by returning the SOA of the parent zone.

Successful DNS query example:
`status: NOERROR`
```bash
; <<>> DiG 9.20.13 <<>> +time=2 +tries=1 google.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 18132
;; flags: qr rd ra ad; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;google.com.                    IN      A

;; ANSWER SECTION:
google.com.             170     IN      A       142.250.195.78

;; Query time: 143 msec
;; SERVER: 192.168.195.146#53(192.168.195.146) (UDP)
;; WHEN: Sat Oct 25 10:24:20 IST 2025
;; MSG SIZE  rcvd: 44
```
Failure DNS query example:
1. `status: NXDOMAIN`
```bash 
; <<>> DiG 9.20.13 <<>> +time=2 +tries=1 running-sigi.de
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 110
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 512
;; QUESTION SECTION:
;running-sigi.de.               IN      A

;; AUTHORITY SECTION:
de.                     1800    IN      SOA     f.nic.de. dns-operations.denic.de. 1761367461 7200 7200 3600000 7200

;; Query time: 176 msec
;; SERVER: 8.8.8.8#53(8.8.8.8) (UDP)
;; WHEN: Sat Oct 25 10:16:16 IST 2025
;; MSG SIZE  rcvd: 107
```

2. `status: SERVFAIL`
```bash
; <<>> DiG 9.20.13 <<>> +time=2 +tries=1 o-ov.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 48166
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 512
; EDE: 23 (Network Error): ([173.201.72.5] rcode=REFUSED for o-ov.com/a)
; EDE: 23 (Network Error): ([97.74.104.5] rcode=REFUSED for o-ov.com/a)
; EDE: 22 (No Reachable Authority): (At delegation o-ov.com for o-ov.com/a)
;; QUESTION SECTION:
;o-ov.com.                      IN      A

;; Query time: 283 msec
;; SERVER: 8.8.8.8#53(8.8.8.8) (UDP)
;; WHEN: Sat Oct 25 10:16:19 IST 2025
;; MSG SIZE  rcvd: 177
```

3. no status at all
```bash
;; communications error to 8.8.8.8#53: timed out

; <<>> DiG 9.20.13 <<>> +time=2 +tries=1 house-sg.com
;; global options: +cmd
;; no servers could be reached
```


## Recursive 💣
- There is no mode where the root will itself recursively query TLD and then the authoritative and then forward the final answer back to you (unless the root server operator also configured their server as an open recursive resolver for your client, which they don’t).