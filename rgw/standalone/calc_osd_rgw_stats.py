#!/usr/bin/env python3
import re
import sys
from collections import defaultdict

if len(sys.argv) != 2:
    print(f"Usage: {sys.argv[0]} <logfile>")
    sys.exit(1)

logfile = sys.argv[1]

# Match daemon name, cpu, memory
pattern = re.compile(
    r"Daemon:\s*(\S+).*?cpu utilisation:\s*([\d.]+)\s*Memory:\s*([\d.]+)",
    re.IGNORECASE,
)

stats = defaultdict(lambda: {"cpu": [], "mem": []})

with open(logfile) as f:
    for line in f:
        m = pattern.search(line)
        if not m:
            continue
        daemon_name, cpu, mem = m.group(1), float(m.group(2)), float(m.group(3))
        name = daemon_name.lower()

        # ---- Updated grouping rules ----
        if name.startswith("osd."):
            group = "osd"
        elif "rgw" in name:  # catches client.rgw.rgw.* etc.
            group = "rgw"
        else:
            continue

        stats[group]["cpu"].append(cpu)
        stats[group]["mem"].append(mem)

if not stats:
    print("No matching osd or rgw entries found.")
    sys.exit(0)

print(
    f"{'Daemon':<8} {'Avg CPU%':>8} {'Max CPU%':>8} {'Avg Mem(MB)':>12} {'Max Mem(MB)':>12}"
)
print("-" * 55)
for group in ["osd", "rgw"]:
    if group in stats:
        c = stats[group]["cpu"]
        m = stats[group]["mem"]
        print(
            f"{group:<8} {sum(c)/len(c):8.2f} {max(c):8.2f} {sum(m)/len(m):12.2f} {max(m):12.2f}"
        )
