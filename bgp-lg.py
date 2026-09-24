#!/usr/bin/env python3
import shutil
import sys

import requests

RIPE_BGP_API = "https://stat.ripe.net/data/bgp-state/data.json"
RIPE_AS_API = "https://stat.ripe.net/data/as-overview/data.json"


def get_bgp_path(ip):
    params = {"resource": ip}
    r = requests.get(RIPE_BGP_API, params=params, timeout=10)
    r.raise_for_status()
    data = r.json()

    paths = data["data"]["bgp_state"]
    if not paths:
        raise Exception("No BGP path found")

    return paths[0]["path"]


def get_as_name(asn):
    params = {"resource": f"AS{asn}"}
    r = requests.get(RIPE_AS_API, params=params, timeout=10)
    r.raise_for_status()
    payload = r.json()
    holder = payload.get("data", {}).get("holder")
    return holder or f"AS{asn}"


def draw_as_graph(path):
    if not path:
        raise ValueError("Path is empty")

    print("\nAS topology:\n")

    terminal_width = shutil.get_terminal_size((80, 20)).columns
    lines = []

    for i, asn in enumerate(path):
        if i == 0:
            lines.append(f"AS{asn}")
        else:
            lines.append("   |")
            lines.append(f"AS{asn}")

    for line in lines:
        print(line)

    print()


def main():
    if len(sys.argv) != 2:
        print("Usage: bgp-lg.py <ip>")
        sys.exit(1)

    ip = sys.argv[1]
    print(f"\n BGP AS Path for {ip}\n")

    path = get_bgp_path(ip)

    for i, asn in enumerate(path, 1):
        name = get_as_name(asn)
        print(f"{i}. AS{asn} — {name}")

    draw_as_graph(path)


if __name__ == "__main__":
    main()
