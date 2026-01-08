#!/usr/bin/env python3

import ipaddress
import requests
from collections import Counter, defaultdict
from pathlib import Path
# Sources below are intentionally duplicated with aggregation for the purposes of adding recency bias and consensus based weighting.
SOURCES = [
    "https://iplists.firehol.org/files/tor_exits_30d.ipset",
    "https://raw.githubusercontent.com/ibell63/lists/refs/heads/master/aggregated/tor_exits/7d.txt",
    "https://raw.githubusercontent.com/ibell63/lists/refs/heads/master/aggregated/tor_exits/1d.txt",
    "https://iplists.firehol.org/files/socks_proxy_30d.ipset",
    "https://raw.githubusercontent.com/ibell63/lists/refs/heads/master/aggregated/socks_proxy/7d.txt",
    "https://raw.githubusercontent.com/ibell63/lists/refs/heads/master/aggregated/socks_proxy/1d.txt",
    "https://iplists.firehol.org/files/sslproxies_30d.ipset",
    "https://raw.githubusercontent.com/ibell63/lists/refs/heads/master/aggregated/sslproxies/7d.txt",
    "https://raw.githubusercontent.com/ibell63/lists/refs/heads/master/aggregated/sslproxies/1d.txt",
    "https://iplists.firehol.org/files/botscout_30d.ipset",
    "https://raw.githubusercontent.com/ibell63/lists/refs/heads/master/aggregated/botscout/7d.txt",
    "https://raw.githubusercontent.com/ibell63/lists/refs/heads/master/aggregated/botscout/1d.txt",
    "https://raw.githubusercontent.com/ibell63/lists/refs/heads/master/aggregated/sblam/7d.txt",
    "https://raw.githubusercontent.com/ibell63/lists/refs/heads/master/aggregated/sblam/1d.txt",
    "https://iplists.firehol.org/files/stopforumspam_365d.ipset",
    "https://iplists.firehol.org/files/stopforumspam_180d.ipset",
    "https://iplists.firehol.org/files/stopforumspam_90d.ipset",
    "https://iplists.firehol.org/files/stopforumspam.ipset",
    "https://iplists.firehol.org/files/stopforumspam_30d.ipset",
    "https://iplists.firehol.org/files/stopforumspam_7d.ipset",
    "https://iplists.firehol.org/files/stopforumspam_1d.ipset",
    "https://raw.githubusercontent.com/ibell63/lists/refs/heads/master/aggregated/blocklist_de_strongips/7d.txt",
    "https://raw.githubusercontent.com/ibell63/lists/refs/heads/master/aggregated/blocklist_de_strongips/1d.txt",
    "https://raw.githubusercontent.com/ibell63/lists/refs/heads/master/aggregated/bruteforceblocker/7d.txt",
    "https://raw.githubusercontent.com/ibell63/lists/refs/heads/master/aggregated/bruteforceblocker/1d.txt",
    "https://iplists.firehol.org/files/dshield_30d.netset",
    "https://raw.githubusercontent.com/ibell63/lists/refs/heads/master/aggregated/dshield/7d.txt",
    "https://raw.githubusercontent.com/ibell63/lists/refs/heads/master/aggregated/dshield/1d.txt",
    "https://raw.githubusercontent.com/ibell63/lists/refs/heads/master/aggregated/et_compromised/7d.txt",
    "https://raw.githubusercontent.com/ibell63/lists/refs/heads/master/aggregated/et_compromised/1d.txt",
    "https://iplists.firehol.org/files/spamhaus_drop.netset",
    "https://iplists.firehol.org/files/et_block.netset",
    "https://iplists.firehol.org/files/blocklist_net_ua.ipset",
    "https://iplists.firehol.org/files/firehol_proxies.netset",
    "https://iplists.firehol.org/files/firehol_level2.netset",
    "https://raw.githubusercontent.com/ibell63/lists/refs/heads/master/aggregated/ipsum_1/7d.txt",
    "https://raw.githubusercontent.com/ibell63/lists/refs/heads/master/aggregated/ipsum_1/1d.txt",
    "https://raw.githubusercontent.com/ibell63/lists/refs/heads/master/aggregated/ipsum_2/7d.txt",
    "https://raw.githubusercontent.com/ibell63/lists/refs/heads/master/aggregated/ipsum_2/1d.txt",
    "https://raw.githubusercontent.com/ibell63/lists/refs/heads/master/aggregated/ipsum_3/7d.txt",
    "https://raw.githubusercontent.com/ibell63/lists/refs/heads/master/aggregated/ipsum_3/1d.txt",
    "https://raw.githubusercontent.com/ibell63/lists/refs/heads/master/aggregated/ipsum_4/7d.txt",
    "https://raw.githubusercontent.com/ibell63/lists/refs/heads/master/aggregated/ipsum_4/1d.txt",
    "https://raw.githubusercontent.com/ibell63/lists/refs/heads/master/aggregated/ipsum_5/7d.txt",
    "https://raw.githubusercontent.com/ibell63/lists/refs/heads/master/aggregated/ipsum_5/1d.txt",
    "https://raw.githubusercontent.com/ibell63/lists/refs/heads/master/aggregated/ipsum_6/7d.txt",
    "https://raw.githubusercontent.com/ibell63/lists/refs/heads/master/aggregated/ipsum_6/1d.txt",
    "https://raw.githubusercontent.com/ibell63/lists/refs/heads/master/aggregated/ipsum_7/7d.txt",
    "https://raw.githubusercontent.com/ibell63/lists/refs/heads/master/aggregated/ipsum_7/1d.txt",
    "https://raw.githubusercontent.com/ibell63/lists/refs/heads/master/aggregated/ipsum_8/7d.txt",
    "https://raw.githubusercontent.com/ibell63/lists/refs/heads/master/aggregated/ipsum_8/1d.txt",
    "https://raw.githubusercontent.com/ibell63/lists/refs/heads/master/iocs/tweetfeed_yearly_ips.txt",
    "https://raw.githubusercontent.com/ibell63/lists/refs/heads/master/iocs/tweetfeed_monthly_ips.txt",
    "https://raw.githubusercontent.com/ibell63/lists/refs/heads/master/iocs/tweetfeed_weekly_ips.txt",
    "https://raw.githubusercontent.com/ibell63/lists/refs/heads/master/aggregated/bds_atif/7d.txt",
    "https://raw.githubusercontent.com/ibell63/lists/refs/heads/master/aggregated/bds_atif/1d.txt",
    "https://raw.githubusercontent.com/ibell63/lists/refs/heads/master/aggregated/ciarmy/7d.txt",
    "https://raw.githubusercontent.com/ibell63/lists/refs/heads/master/aggregated/ciarmy/1d.txt",
    "https://raw.githubusercontent.com/ibell63/lists/refs/heads/master/aggregated/blocklist_de/7d.txt",
    "https://raw.githubusercontent.com/ibell63/lists/refs/heads/master/aggregated/blocklist_de/1d.txt",
    "https://raw.githubusercontent.com/ibell63/lists/refs/heads/master/aggregated/threatView/7d.txt",
    "https://raw.githubusercontent.com/ibell63/lists/refs/heads/master/aggregated/threatView/1d.txt"
]
# Sources above are intentionally duplicated with aggregation for the purposes of adding recency bias and consensus based weighting.
OUTPUT_FILE = Path("output/aggregated.txt")
MAX_LINES = 10_000
PROMOTE_THRESHOLD = 230

def fetch_ips(url):
    response = requests.get(url, timeout=30)
    response.raise_for_status()

    for line in response.text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            yield ipaddress.ip_address(line)
        except ValueError:
            continue

def main():
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    ip_counts = Counter()
    for source in SOURCES:
        for ip in fetch_ips(source):
            ip_counts[ip] += 1

    if not ip_counts:
        OUTPUT_FILE.write_text("")
        return

    net24_counts = Counter()
    net16_to_24s = defaultdict(set)

    for ip, count in ip_counts.items():
        net24 = ipaddress.ip_network((ip, 24), strict=False)
        net16 = ipaddress.ip_network((ip, 16), strict=False)

        net24_counts[net24] += count
        net16_to_24s[net16].add(net24)

    promoted_16s = {
        net16: len(net24s)
        for net16, net24s in net16_to_24s.items()
        if len(net24s) >= PROMOTE_THRESHOLD
    }

    remaining_24s = {
        net24: count
        for net24, count in net24_counts.items()
        if ipaddress.ip_network((net24.network_address, 16), strict=False)
        not in promoted_16s
    }

    sorted_16s = sorted(
        promoted_16s.items(),
        key=lambda x: x[1],
        reverse=True
    )

    sorted_24s = sorted(
        remaining_24s.items(),
        key=lambda x: x[1],
        reverse=True
    )

    lines = []

    for net16, _ in sorted_16s:
        if len(lines) >= MAX_LINES:
            break
        octets = str(net16.network_address).split(".")[:2]
        lines.append(".".join(octets) + ".")

    for net24, _ in sorted_24s:
        if len(lines) >= MAX_LINES:
            break
        octets = str(net24.network_address).split(".")[:3]
        lines.append(".".join(octets) + ".")

    lines = list(dict.fromkeys(lines))[:MAX_LINES]

    OUTPUT_FILE.write_text("\n".join(lines) + "\n")

if __name__ == "__main__":
    main()
