import seaborn as sns
import pandas as pd
import matplotlib.pyplot as plt

data = pd.read_csv('dns_logs1.csv')




# Group by client IP and compute cache hit percentages
groups = data.groupby('Client IP')

overall_hits = 0
overall_total = 0

print("\n" * 4)

for client_ip, group in groups:
    hits = len(group[group['Cache Status'] == 'HIT'])
    total = len(group)
    cache_percentage = (hits / total) * 100

    print(f"Cache hit percentage for {client_ip:<15}: {cache_percentage:.2f}%")

    overall_hits += hits
    overall_total += total

# Avoid division by zero
overall_percentage = (overall_hits / overall_total * 100) if overall_total > 0 else 0

print(f"\nOverall cache hit percentage: {overall_percentage:.2f}%")
print("\n" * 4)




# simple filter (elementwise OR)
filtered_data = data[(data['Response type'] == 'Failure') | (data['Response type'] == 'Response')]

# coerce numeric columns so mean works
filtered_data['Cumulative Time(ms)'] = pd.to_numeric(filtered_data['Cumulative Time(ms)'], errors='coerce')
filtered_data['Cumulative Bytes'] = pd.to_numeric(filtered_data['Cumulative Bytes'], errors='coerce')

grouped = filtered_data.groupby('Client IP')

def fmt(x):
    return "N/A" if pd.isna(x) else f"{x:.2f}"

print('\n\n\n\n')

for client_ip, group in grouped:
    # total_queries = len(group)
    # failed_queries = int((group['Response type'] == 'Failure').sum())
    # success_queries = int((group['Response type'] == 'Response').sum())

    avg_latency = group['Cumulative Time(ms)'].mean()
    avg_bytes = group['Cumulative Bytes'].mean()
    

    if pd.isna(avg_latency) or avg_latency == 0 or pd.isna(avg_bytes):
        avg_throughput = float('nan')
    else:
        avg_throughput = avg_bytes / avg_latency

    print(f"Client IP: {client_ip}")
    # print(f"Total Queries: {total_queries}")
    # print(f"Successful Queries: {success_queries}")
    # print(f"Failed Queries: {failed_queries}")
    print(f"Average Latency (ms): {fmt(avg_latency)}")
    print(f"Average Bytes: {fmt(avg_bytes)}")
    print(f"Average Throughput (bytes/s): {fmt(avg_throughput * 1000)}")
    print("-" * 40)


print('\n\n\n\n')


filtered_data = data.loc[data['Client IP'].isin(['10.0.0.1'])]
# Group by domain
grouped = filtered_data.groupby('Domain',sort=False)

servers_used = []
domains = []
latencies = []
remaining = 20

for domain, group in grouped:
    if remaining == 0:
        break

    # skip domains with no successful response rows
    if not (group['Response type'] == 'Response').any():
        continue

    miss_count = group['Cache Status'].astype(str).isin(['MISS']).sum()
    latency = group[group['Response type'] == 'Response']['Cumulative Time(ms)'].iloc[-1]
    servers_used.append(miss_count)
    domains.append(domain)
    latencies.append(latency)
    remaining -= 1






# First line plot — number of server queries
plt.figure(figsize=(max(6, len(domains)*0.6), 4))
plt.plot(domains, servers_used, marker='o', linewidth=2.5, color='#1f77b4')
plt.xticks(rotation=45, ha='right')
plt.ylabel("Server Queries Made", fontsize=12)

plt.title(f"Top {len(domains)} Domains for Client(s) 10.0.0.1", fontsize=14, weight='bold')
plt.grid(True, linestyle='--', alpha=0.6)
plt.tight_layout()
plt.show()

# Second line plot — latency
plt.figure(figsize=(max(6, len(domains)*0.6), 4))
plt.plot(domains, latencies, marker='o', linewidth=2.5, color='#ff7f0e')
plt.xticks(rotation=45, ha='right')
plt.ylabel("Latency (ms)", fontsize=12)
plt.title(f"Latency for Top {len(domains)} Domains (Client 10.0.0.1)", fontsize=14, weight='bold')
plt.grid(True, linestyle='--', alpha=0.6)
plt.tight_layout()
plt.show()
