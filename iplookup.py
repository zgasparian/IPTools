#!/usr/bin/env python3
"""
iplookup.py - Find out who is behind an IP address

Author:  Zareh Kasparian
Updated: 2026-09-24

What it does
    Asks for an IP address (IPv4 or IPv6) and reports:
      1. BGP prefix and origin ASN that announces the IP
      2. ASN holder (the organisation that owns the AS)
      3. Reverse DNS (PTR) hostname
      4. Every IPv4 / IPv6 prefix announced by that ASN

    If the IP is not announced in BGP (no ASN), it shows the registry (whois)
    record instead: block, net name, country, org and allocation status.

Usage
    ./iplookup.py
    Enter IP address: 8.8.8.8

Output
    Printed on screen, and saved as AS<number>_prefixes.txt in the current
    directory (for example AS15169_prefixes.txt).

Data source
    RIPEstat public API (https://stat.ripe.net/data): network-info,
    as-overview, announced-prefixes, whois and rir-geo.

Requirements
    Python 3 and the 'requests' module. Needs internet access.
"""

import sys
import socket
import ipaddress
import requests


BASE_URL = "https://stat.ripe.net/data"


def ripe_query(endpoint, resource):
    """Query a RIPEstat API endpoint."""
    url = f"{BASE_URL}/{endpoint}/data.json"
    
    try:
        response = requests.get(
            url,
            params={"resource": resource},
            timeout=15
        )
        response.raise_for_status()
        return response.json().get("data", {})
    except requests.RequestException as e:
        print(f"ERROR: Could not query RIPEstat: {e}")
        return {}


def reverse_dns(ip):
    """Try to resolve reverse DNS."""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except (socket.herror, socket.gaierror):
        return "No reverse DNS record"


def print_registry_info(ip):
    """Show what the RIR/whois database says about an IP with no BGP route."""
    whois = ripe_query("whois", ip)

    # Each record group is a list of {key, value}; the first one with an
    # inetnum/inet6num key is the block that covers the IP.
    block = {}
    for group in whois.get("records", []):
        keys = {r["key"]: r["value"] for r in group}
        if "inetnum" in keys or "inet6num" in keys:
            block = keys
            break

    geo = ripe_query("rir-geo", ip).get("located_resources", [])

    print("\n" + "=" * 60)
    print("REGISTRY INFORMATION (whois)")
    print("=" * 60)

    if block:
        print(f"Block      : {block.get('inetnum') or block.get('inet6num')}")
        print(f"Net name   : {block.get('netname', 'Unknown')}")
        print(f"Country    : {block.get('country', 'Unknown')}")
        print(f"Org        : {block.get('org', 'Unknown')}")
        print(f"Status     : {block.get('status', 'Unknown')}")
    else:
        print("No whois record found in the RIPE database.")

    if geo:
        print(f"RIR geo    : {geo[0].get('location', 'Unknown')} ({geo[0].get('resource')})")

    print("\n" + "=" * 60)
    print("DNS INFORMATION")
    print("=" * 60)

    print(f"Hostname   : {reverse_dns(ip)}")


def main():

    # Ask for IP
    ip = input("Enter IP address: ").strip()

    # Validate IP
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        print("Invalid IP address.")
        sys.exit(1)

    print("\nQuerying RIPEstat...\n")

    # ---------------------------------------------------------
    # 1. Network information
    # ---------------------------------------------------------

    network = ripe_query("network-info", ip)

    if not network:
        print("Could not find network information.")
        sys.exit(1)

    prefix = network.get("prefix", "Unknown")
    asns = network.get("asns", [])

    print("=" * 60)
    print("IP INFORMATION")
    print("=" * 60)

    print(f"IP Address : {ip}")

    if not asns:
        # Not announced in BGP: there is no ASN or prefix to report, but the
        # registry (RIPE database) still knows who the block belongs to.
        print("BGP Prefix : Not announced")
        print("ASN        : None (this IP is not announced in BGP)")
        print_registry_info(ip)
        return

    print(f"BGP Prefix : {prefix}")
    print(f"ASN        : AS{asns[0]}")
    asn = f"AS{asns[0]}"

    # ---------------------------------------------------------
    # 2. ASN overview
    # ---------------------------------------------------------

    overview = ripe_query("as-overview", asn)

    print("\n" + "=" * 60)
    print("ASN INFORMATION")
    print("=" * 60)

    print(f"ASN        : {asn}")
    print(f"Holder     : {overview.get('holder', 'Unknown')}")
    print(f"Announcing : {overview.get('announcing', 'Unknown')}")

    # ---------------------------------------------------------
    # 3. Reverse DNS
    # ---------------------------------------------------------

    hostname = reverse_dns(ip)

    print("\n" + "=" * 60)
    print("DNS INFORMATION")
    print("=" * 60)

    print(f"Hostname   : {hostname}")

    # ---------------------------------------------------------
    # 4. All announced prefixes
    # ---------------------------------------------------------

    announced = ripe_query("announced-prefixes", asn)

    prefixes = announced.get("prefixes", [])

    ipv4_prefixes = []
    ipv6_prefixes = []

    for item in prefixes:

        p = item.get("prefix")

        if not p:
            continue

        try:
            network_obj = ipaddress.ip_network(p, strict=False)

            if network_obj.version == 4:
                ipv4_prefixes.append(p)
            else:
                ipv6_prefixes.append(p)

        except ValueError:
            pass

    # Sort prefixes
    ipv4_prefixes.sort(
        key=lambda x: (
            int(ipaddress.ip_network(x).network_address),
            ipaddress.ip_network(x).prefixlen
        )
    )

    ipv6_prefixes.sort()

    # ---------------------------------------------------------
    # 5. Display IPv4 prefixes
    # ---------------------------------------------------------

    print("\n" + "=" * 60)
    print(f"ANNOUNCED IPv4 PREFIXES ({len(ipv4_prefixes)})")
    print("=" * 60)

    for p in ipv4_prefixes:
        print(p)

    # ---------------------------------------------------------
    # 6. Display IPv6 prefixes
    # ---------------------------------------------------------
    # ---------------------------------------------------------
    # 7. Save results
    # ---------------------------------------------------------

    filename = f"{asn}_prefixes.txt"

    with open(filename, "w") as f:

        f.write(f"IP Address: {ip}\n")
        f.write(f"BGP Prefix: {prefix}\n")
        f.write(f"ASN: {asn}\n")
        f.write(f"Holder: {overview.get('holder', 'Unknown')}\n")
        f.write(f"Reverse DNS: {hostname}\n\n")

        f.write("=" * 60 + "\n")
        f.write(f"IPv4 Prefixes ({len(ipv4_prefixes)})\n")
        f.write("=" * 60 + "\n")

        for p in ipv4_prefixes:
            f.write(p + "\n")

        f.write("\n")
        f.write("=" * 60 + "\n")
        f.write(f"IPv6 Prefixes ({len(ipv6_prefixes)})\n")
        f.write("=" * 60 + "\n")

        for p in ipv6_prefixes:
            f.write(p + "\n")

    print("\n" + "=" * 60)
    print(f"Results saved to: {filename}")
    print("=" * 60)


if __name__ == "__main__":
    main()
