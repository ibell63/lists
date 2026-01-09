#!/usr/bin/env python3

import requests
from pathlib import Path
from datetime import datetime, timedelta

BASE_DIR = Path("aggregated")

SOURCES = [
    {
        "name": "ciarmy",
        "url": "https://iplists.firehol.org/files/ciarmy.ipset"
    },
    {
        "name": "bds_atif",
        "url": "https://iplists.firehol.org/files/bds_atif.ipset"
    },
    {
        "name": "blocklist_de",
        "url": "https://iplists.firehol.org/files/blocklist_de.ipset"
    },
    {
        "name": "ipsum_1",
        "url": "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/1.txt"
    },
    {
        "name": "ipsum_2",
        "url": "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/2.txt"
    },
    {
        "name": "ipsum_3",
        "url": "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt"
    },
    {
        "name": "ipsum_4",
        "url": "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/4.txt"
    },
    {
        "name": "ipsum_5",
        "url": "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/5.txt"
    },
    {
        "name": "ipsum_6",
        "url": "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/6.txt"
    },
    {
        "name": "ipsum_7",
        "url": "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/7.txt"
    },
    {
        "name": "ipsum_8",
        "url": "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/8.txt"
    },
    {
        "name": "threatView",
        "url": "https://threatview.io/Downloads/IP-High-Confidence-Feed.txt"
    },
    {
        "name": "tor_exits",
        "url": "https://iplists.firehol.org/files/tor_exits_1d.ipset"
    },
    {
        "name": "dshield",
        "url": "https://iplists.firehol.org/files/dshield_1d.netset"
    },
    {
        "name": "socks_proxy",
        "url": "https://iplists.firehol.org/files/socks_proxy_1d.ipset"
    },
    {
        "name": "sslproxies",
        "url": "https://iplists.firehol.org/files/sslproxies_1d.ipset"
    },
    {
        "name": "botscout",
        "url": "https://iplists.firehol.org/files/botscout_1d.ipset"
    },
    {
        "name": "sblam",
        "url": "https://iplists.firehol.org/files/sblam.ipset"
    },
    {
        "name": "blocklist_de_strongips",
        "url": "https://iplists.firehol.org/files/blocklist_de_strongips.ipset"
    },
    {
        "name": "bruteforceblocker",
        "url": "https://iplists.firehol.org/files/bruteforceblocker.ipset"
    },
    {
        "name": "et_compromised",
        "url": "https://iplists.firehol.org/files/et_compromised.ipset"
    },
    {
        "name": "hagezi_tif_ips",
        "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/ips/tif.txt"
    },
    {
        "name": "tweetfeed",
        "url": "https://raw.githubusercontent.com/ibell63/lists/refs/heads/master/iocs/tweetfeed_weekly_ips.txt"
    },
    {
        "name": "et_block",
        "url": "https://iplists.firehol.org/files/et_block.netset"
    },
    {
        "name": "et_spamhaus",
        "url": "https://iplists.firehol.org/files/et_spamhaus.netset"
    },
    {
        "name": "et_tor",
        "url": "https://iplists.firehol.org/files/et_tor.ipset"
    }
  
]

WINDOWS = {
    "1d": 1, # normalized daily mirror of source feed
    "7d": 7,
    "30d": 30,
    "90d": 90
}

TODAY = datetime.utcnow().date()


def fetch_ips(url):
    r = requests.get(url, timeout=30)
    r.raise_for_status()
    return {
        line.strip()
        for line in r.text.splitlines()
        if line.strip() and not line.startswith("#")
    }


def load_ips_from_file(path):
    return {
        line.strip()
        for line in path.read_text().splitlines()
        if line.strip()
    }


for source in SOURCES:
    name = source["name"]
    url = source["url"]

    source_dir = BASE_DIR / name
    raw_dir = source_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    today_file = raw_dir / f"{TODAY}.txt"

    # Fetch & store today's snapshot
    ips_today = fetch_ips(url)
    today_file.write_text("\n".join(sorted(ips_today)) + "\n")

    # Build aggregates
    for label, days in WINDOWS.items():
        cutoff = TODAY - timedelta(days=days - 1)
        all_ips = set()

        for raw_file in raw_dir.glob("*.txt"):
            file_date = datetime.strptime(raw_file.stem, "%Y-%m-%d").date()
            if file_date >= cutoff:
                all_ips |= load_ips_from_file(raw_file)

        out_file = source_dir / f"{label}.txt"
        out_file.write_text("\n".join(sorted(all_ips)) + "\n")

    # --- Limit growth per feed ---
    MAX_RAW_DAYS = 100
    raw_files = sorted(raw_dir.glob("*.txt"))
    if len(raw_files) > MAX_RAW_DAYS:
        for old_file in raw_files[:-MAX_RAW_DAYS]:
            print(f"Removing old raw snapshot: {old_file}")
            old_file.unlink()
