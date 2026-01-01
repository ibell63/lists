#!/usr/bin/env python3

import ipaddress
import requests
from collections import Counter, defaultdict
from pathlib import Path

# =========================
# CONFIGURATION
# =========================

SOURCES = [
    "https://example.com/list1.txt",
    "https://example.com/list2.txt",
    # add more sources here
]

OUTPUT_FILE = Path("output/aggregated.txt")
MAX_LINES = 10_000
PROMOTE_THRESHOLD = 10  # number of /24s in a /16 required to promote

# =========================
# FETCH + PARSE
# =========================

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

# =========================
# MAIN
# =========================

def main():
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    # Collect IPs
    ip_counts = Counter()

    for source in SOURCES:
        for ip in fetch_ips(source):
            ip_counts[ip] += 1

    if not ip_counts:
        OUTPUT_FILE.write_text("")
        return

    # Aggregate
    net24_counts = Counter()
    net16_to_24s = defaultdict(set)

    for ip, count in ip_counts.items():
        net24 = ipaddress.ip_network((ip, 24), strict=False)
        net16 = ipaddress.ip_network((ip, 16), strict=False)

        net24_counts[net24] += count
        net16_to_24s[net16].add(net24)

    # Promote /16s
    promoted_16s = {
        net16: len(net24s)
        for net16, net24s in net16_to_24s.items()
        if len(net24s) >= PROMOTE_THRESHOLD
    }

    # Keep /24s not covered by promoted /16s
    remaining_24s = {
        net24: count
        for net24, count in net24_counts.items()
        if ipaddress.ip_network((net24.network_address, 16), strict=False)
        not in promoted_16s
    }

    # Sort by prevalence
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

    # Build output
    lines = []

    for net16, _ in sorted_16s:
        if len(lines) >= MAX_LINES:
            break
        octets = str(net16.network_address).split(".")[:2]
        lines.append(".".join(octets))

    for net24, _ in sorted_24s:
        if len(lines) >= MAX_LINES:
            break
        octets = str(net24.network_address).split(".")[:3]
        lines.append(".".join(octets))

    # Deduplicate while preserving order
    lines = list(dict.fromkeys(lines))[:MAX_LINES]

    OUTPUT_FILE.write_text("\n".join(lines) + "\n")

if __name__ == "__main__":
    main()
