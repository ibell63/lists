#!/usr/bin/env python3

import ipaddress
import requests
from collections import defaultdict, Counter
from pathlib import Path

# =========================
# CONFIGURATION
# =========================

SOURCES = [
    "https://iplists.firehol.org/files/tor_exits_30d.ipset",
    "https://iplists.firehol.org/files/socks_proxy_30d.ipset",
    "https://iplists.firehol.org/files/sslproxies_30d.ipset",
    "https://iplists.firehol.org/files/botscout_30d.ipset",
    "https://iplists.firehol.org/files/sblam.ipset",
    "https://iplists.firehol.org/files/stopforumspam_365d.ipset",
    "https://iplists.firehol.org/files/stopforumspam_1d.ipset",
    "https://iplists.firehol.org/files/blocklist_de.ipset",
    "https://iplists.firehol.org/files/blocklist_de_strongips.ipset",
    "https://iplists.firehol.org/files/bruteforceblocker.ipset",
    "https://iplists.firehol.org/files/dshield_30d.netset",
    "https://iplists.firehol.org/files/et_compromised.ipset",
    "https://iplists.firehol.org/files/greensnow.ipset",
    "https://iplists.firehol.org/files/bds_atif.ipset",
    "https://iplists.firehol.org/files/ciarmy.ipset",
    "https://iplists.firehol.org/files/spamhaus_drop.netset",
    "https://iplists.firehol.org/files/et_block.netset",
    "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/1.txt",
    "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/2.txt",
    "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt",
    "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/4.txt"
    # add more here
]

OUTPUT_FILE = Path("output/aggregated.txt")
MAX_LINES = 10_000
PROMOTE_THRESHOLD = 10  # /24s per /16

# =========================
# FETCH + PARSE
# =========================

def fetch_ips(url):
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    for line in resp.text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            yield ipaddress.ip_address(line)
        except ValueError:
            continue

# =========================
# MAIN LOGIC
# =========================

def main():
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    all_ips = []

    for url in SOURCES:
        all_ips.extend(fetch_ips(url))

    # Count exact IPs
    ip_counts = Counter(all_ips)

    # Aggregate to /24
    net24_counts = Counter()
    net16_to_24s = defaultdict(set)

    for ip, count in ip_counts.items():
        net24 = ipaddress.ip_network(f"{ip}/24", strict=False)
        net16 = ipaddress.ip_network(f"{ip}/16", strict=False)

        net24_counts[net24] += count
        net16_to_24s[net16].add(net24)

    # Decide which /16s get promoted
    promoted_16s = {
        net16: len(net24s)
        for net16, net24s in net16_to_24s.items()
        if len(net24s) >= PROMOTE_THRESHOLD
    }

    # Remaining /24s (not covered by promoted /16s)
    remaining_24s = {
        net24: count
        for net24, count in net24_counts.items()
        if ipaddress.ip_network(f"{net24.network_address}/16", strict=False)
        not in promoted_16s
    }

    # =========================
    # SORTING
    # =========================

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

    # =========================
    # OUTPUT WITH LIMIT
    # =========================

    lines = []

    for net16, count in sorted_16s:
        if len(lines) >= MAX_LINES:
            break
        lines.append(f"{net16}  # {count} /24s")

    for net24, count in sorted_24s:
        if len(lines) >= MAX_LINES:
            break
        lines.append(f"{net24}  # {count} IPs")

    OUTPUT_FILE.write_text("\n".join(lines) + "\n")

    print(f"Wrote {len(lines)} entries to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
