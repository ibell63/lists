#!/usr/bin/env python3

import ipaddress
import requests
from collections import Counter, defaultdict
from pathlib import Path

SOURCES = [
    "https://iplists.firehol.org/files/tor_exits_30d.ipset",
    "https://iplists.firehol.org/files/tor_exits_7d.ipset",
    "https://iplists.firehol.org/files/tor_exits_1d.ipset",
    "https://iplists.firehol.org/files/tor_exits.ipset",
    "https://iplists.firehol.org/files/socks_proxy_30d.ipset",
    "https://iplists.firehol.org/files/socks_proxy_7d.ipset",
    "https://iplists.firehol.org/files/socks_proxy_1d.ipset",
    "https://iplists.firehol.org/files/sslproxies_30d.ipset",
    "https://iplists.firehol.org/files/sslproxies_7d.ipset",
    "https://iplists.firehol.org/files/sslproxies_1d.ipset",
    "https://iplists.firehol.org/files/botscout_30d.ipset",
    "https://iplists.firehol.org/files/botscout_7d.ipset",
    "https://iplists.firehol.org/files/botscout_1d.ipset",
    "https://iplists.firehol.org/files/sblam.ipset",
    "https://iplists.firehol.org/files/stopforumspam_365d.ipset",
    "https://iplists.firehol.org/files/stopforumspam_180d.ipset",
    "https://iplists.firehol.org/files/stopforumspam_90d.ipset",
    "https://iplists.firehol.org/files/stopforumspam.ipset",
    "https://iplists.firehol.org/files/stopforumspam_30d.ipset",
    "https://iplists.firehol.org/files/stopforumspam_7d.ipset",
    "https://iplists.firehol.org/files/stopforumspam_1d.ipset",
    "https://iplists.firehol.org/files/blocklist_de.ipset",
    "https://iplists.firehol.org/files/blocklist_de_strongips.ipset",
    "https://iplists.firehol.org/files/bruteforceblocker.ipset",
    "https://iplists.firehol.org/files/dshield_30d.netset",
    "https://iplists.firehol.org/files/dshield_7d.netset",
    "https://iplists.firehol.org/files/dshield_1d.netset",
    "https://iplists.firehol.org/files/dshield.netset",
    "https://iplists.firehol.org/files/et_compromised.ipset",
    "https://iplists.firehol.org/files/greensnow.ipset",
    "https://iplists.firehol.org/files/bds_atif.ipset",
    "https://iplists.firehol.org/files/ciarmy.ipset",
    "https://iplists.firehol.org/files/spamhaus_drop.netset",
    "https://iplists.firehol.org/files/et_block.netset",
    "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/2.txt",
    "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt",
    "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/4.txt",
    "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/5.txt",
    "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/6.txt",
    "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/7.txt",
    "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/8.txt",
    "https://iplists.firehol.org/files/blocklist_net_ua.ipset"
]

OUTPUT_FILE = Path("output/aggregated.txt")
MAX_LINES = 10_000
PROMOTE_THRESHOLD = 10

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
