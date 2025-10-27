## Project Structure

1. **`topo.py`** – Simulates the network topology for **Part (a)** of the assignment.  
2. **`main.py`** – Implements the core logic for **Parts (b)**, **(c)**, and **(d)**.  
3. **`client.py`** – Reads the input pcap file specified as a command-line argument and asks dns queries to `server.py`
4. **`server.py`** – Implements a custom **recursive DNS resolver** with caching, fulfilling the requirements of **Parts (e)** and **(f)**.

---

### Output Files

- **`dns_logs1.csv`** – Contains the logged DNS query results.  
- **`A2_report.pdf`** – Detailed report explaining the implementation and results.

---

### Overview

This project simulates a DNS environment where a recursive resolver is implemented and tested within a Mininet-based topology.  The resolver supports caching and handles recursive queries as per the assignment requirements.