#!/usr/bin/python3
import requests

asn = input("Enter AS number (e.g. AS58224): ").strip().upper()

if not asn.startswith("AS"):
    asn = "AS" + asn

url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource={asn}"

response = requests.get(url)
response.raise_for_status()

data = response.json()

for item in data["data"]["prefixes"]:
    print(item["prefix"])
