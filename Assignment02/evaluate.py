import pandas as pd
import matplotlib.pyplot as plt

data = pd.read_csv('dns_logs1.csv')

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
    total_queries = len(group)
    failed_queries = int((group['Response type'] == 'Failure').sum())
    success_queries = int((group['Response type'] == 'Response').sum())

    avg_latency = group['Cumulative Time(ms)'].mean()
    avg_bytes = group['Cumulative Bytes'].mean()

    if pd.isna(avg_latency) or avg_latency == 0 or pd.isna(avg_bytes):
        avg_throughput = float('nan')
    else:
        avg_throughput = avg_bytes / avg_latency

    print(f"Client IP: {client_ip}")
    print(f"Total Queries: {total_queries}")
    print(f"Successful Queries: {success_queries}")
    print(f"Failed Queries: {failed_queries}")
    print(f"Average Latency (ms): {fmt(avg_latency)}")
    print(f"Average Bytes: {fmt(avg_bytes)}")
    print(f"Average Throughput (bytes/ms): {fmt(avg_throughput)}")
    print("-" * 40)


print('\n\n\n\n')


filtered_data = data.loc[data['Client IP'].isin(['10.0.0.1'])]
# Group by domain
grouped = filtered_data.groupby('Domain')

servers_used = []
domains = []
latencies = []
remaining = 40

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



plt.figure(figsize=(max(6, len(domains)*0.6), 4))
plt.bar(domains, servers_used)
plt.xticks(rotation=45, ha='right')
plt.ylabel("Server queries made")
plt.title(f"Top {len(domains)} domains for client(s) 10.0.0.1")
plt.tight_layout()
plt.show()


plt.figure(figsize=(max(6, len(domains)*0.6), 4))
plt.bar(domains, latencies)
plt.xticks(rotation=45, ha='right')
plt.ylabel("Latency")
plt.title(f"Top {len(domains)} domains for client(s) 10.0.0.1")
plt.tight_layout()
plt.show()