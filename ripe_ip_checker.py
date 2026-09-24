#!/usr/bin/env python3
"""
ripe_ip_checker.py - Pre-purchase due-diligence report for IPv4 ranges (RIPE NCC region)

Asks for one or more supernets and produces a plain-text report covering:

   1. Registry ownership & status      (RIPE Database)
   2. Transfer history                 (RIPE NCC transfer statistics, historical whois)
   3. BGP / routing history            (RIPEstat / RIS)
   4. RPKI (ROAs) & IRR route objects   (RIPEstat, RADB whois mirror of all major IRRs)
   5. IP reputation                    (Spamhaus DROP, DNSBLs, FireHOL, Tor, optional APIs)
   6. Geolocation                      (RIPE DB, MaxMind GeoLite via RIPEstat, ipinfo)
   7. Past-usage fingerprints          (reverse DNS, PTR names, abuse contact, Shodan)
   8. Legal & compliance               (seller identity, sanctions, manual checklist)
   9. Structure & fragmentation        (size, alignment, sub-assignments, aggregation)

Only the Python standard library is required (Python 3.8+).

Optional API keys (environment variables) enable extra checks:
   ABUSEIPDB_API_KEY   AbuseIPDB abuse reports per /24          (free account)
   IPQS_API_KEY        IPQualityScore fraud score / VPN / proxy  (free account)
   OTX_API_KEY         AlienVault OTX threat-intel pulses        (free account)
   GREYNOISE_API_KEY   GreyNoise community API (works without key, rate limited)
   IPINFO_TOKEN        ipinfo.io geolocation (works without token, rate limited)
   SHODAN_API_KEY      Shodan exposed services history
   SPAMHAUS_DQS_KEY    Spamhaus DQS key (needed if your DNS resolver is a public one)
   OPENSANCTIONS_API_KEY  Automated sanctions screening of the holder organisation

Usage:
   python3 ripe_ip_checker.py                       # interactive prompt
   python3 ripe_ip_checker.py 193.0.0.0/21 91.198.174.0/24
   python3 ripe_ip_checker.py 193.0.0.0/21 --full-dnsbl --output-dir reports
"""

import argparse
import concurrent.futures as cf
import datetime as dt
import ipaddress
import json
import os
import re
import socket
import sys
import tempfile
import textwrap
import time
import urllib.error
import urllib.parse
import urllib.request

VERSION = "1.0"
WIDTH = 100
UA = f"ripe-ip-checker/{VERSION} (IP range pre-purchase due diligence)"

RIPESTAT = "https://stat.ripe.net/data/{}/data.json"
RIPE_DB = "https://rest.db.ripe.net"
TRANSFERS_URL = "https://ftp.ripe.net/pub/stats/ripencc/transfers/transfers_latest.json"
DROP_URL = "https://www.spamhaus.org/drop/drop_v4.json"
TOR_URL = "https://check.torproject.org/torbulkexitlist"
FIREHOL_BASE = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/"
FIREHOL_LISTS = [
    # (file, severity if hit, description)
    ("firehol_level1.netset", "HIGH", "Level 1 - highest-confidence attack/abuse sources (incl. DROP)"),
    ("firehol_level2.netset", "MEDIUM", "Level 2 - attacks/abuse seen in the last 48 hours"),
    ("firehol_level3.netset", "MEDIUM", "Level 3 - attacks, spyware, viruses in the last 30 days"),
    ("firehol_abusers_30d.netset", "LOW", "Abusers - aggregated abuse lists, last 30 days"),
]
IRR_WHOIS = "whois.radb.net"   # RADB mirrors RIPE, ARIN, APNIC, ALTDB, NTTCOM, LEVEL3, etc.

CACHE_DIR = os.path.join(os.path.expanduser("~"), ".cache", "ripe-ip-checker")
NOW = dt.datetime.now(dt.timezone.utc)

MAX_24S = 256          # per-/24 checks are sampled above this many /24s
API_SAMPLE_CAP = 20    # max IPs sent to rate-limited third-party APIs
SAMPLE_OFFSETS = (1, 10, 100, 200, 254)

HIGH_RISK_COUNTRIES = {
    "RU": "Russia", "BY": "Belarus", "IR": "Iran", "KP": "North Korea",
    "SY": "Syria", "CU": "Cuba",
}
HOLDER_STATUSES = {
    "ALLOCATED PA", "ALLOCATED-ASSIGNED PA", "ALLOCATED PI",
    "ASSIGNED PI", "ASSIGNED ANYCAST", "LEGACY",
}
REGISTRY_ORGS = {"ORG-IANA1-RIPE", "ORG-NCC1-RIPE"}

# Severity levels, most severe first
CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN, INFO, OK = (
    "CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN", "INFO", "OK")
SEV_ORDER = [CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN, INFO, OK]


# =====================================================================================
#  Generic helpers
# =====================================================================================

def wrap(text, width):
    return textwrap.wrap(text, width, break_long_words=False, break_on_hyphens=False)


def log(msg):
    print(f"  [*] {msg}", file=sys.stderr, flush=True)


def parse_dt(value):
    if not value:
        return None
    s = str(value).strip().replace("Z", "+00:00")
    try:
        d = dt.datetime.fromisoformat(s)
    except ValueError:
        try:
            d = dt.datetime.strptime(s[:10], "%Y-%m-%d")
        except ValueError:
            return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=dt.timezone.utc)
    return d


def fmt_date(d):
    return d.strftime("%Y-%m-%d") if d else "-"


def add_months(d, months):
    y, m = divmod(d.month - 1 + months, 12)
    day = min(d.day, 28)
    return d.replace(year=d.year + y, month=m + 1, day=day)


def ip2int(ip):
    return int(ipaddress.IPv4Address(ip))


def int2ip(n):
    return str(ipaddress.IPv4Address(n))


def range_to_cidrs(start, end):
    return [str(c) for c in ipaddress.summarize_address_range(
        ipaddress.IPv4Address(start), ipaddress.IPv4Address(end))]


def overlap_size(a_start, a_end, b_start, b_end):
    return max(0, min(a_end, b_end) - max(a_start, b_start) + 1)


def norm_name(name):
    n = re.sub(r"[^a-z0-9 ]", " ", (name or "").lower())
    n = re.sub(r"\b(ltd|llc|limited|gmbh|bv|b v|sa|s a|srl|sro|s r o|inc|oy|ab|as|ooo|plc|"
               r"sp z o o|spa|kft|doo|d o o|ug|ag|co|company|corp|corporation)\b", " ", n)
    return " ".join(n.split())


def pmap(func, items, workers=16):
    """Parallel map that keeps order and never raises."""
    def safe(x):
        try:
            return func(x)
        except Exception as e:   # noqa: BLE001 - one failed lookup must not stop the report
            return e
    items = list(items)
    if not items:
        return []
    with cf.ThreadPoolExecutor(max_workers=min(workers, len(items))) as ex:
        return list(ex.map(safe, items))


def http_get(url, headers=None, timeout=30, data=None, retries=2):
    """Return (status_code, body_bytes). status_code 0 means a network error."""
    hdrs = {"User-Agent": UA, "Accept": "application/json"}
    hdrs.update(headers or {})
    last_err = None
    for attempt in range(retries + 1):
        req = urllib.request.Request(url, headers=hdrs, data=data)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            body = e.read() or b""
            if e.code in (429, 500, 502, 503, 504) and attempt < retries:
                time.sleep(2 * (attempt + 1))
                continue
            return e.code, body
        except Exception as e:   # noqa: BLE001
            last_err = e
            if attempt < retries:
                time.sleep(1.5 * (attempt + 1))
    return 0, str(last_err).encode()


def http_json(url, **kw):
    status, body = http_get(url, **kw)
    try:
        data = json.loads(body.decode("utf-8", "replace")) if body else None
    except ValueError:
        data = None
    return status, data


def cache_path(name):
    for base in (CACHE_DIR, os.path.join(tempfile.gettempdir(), "ripe-ip-checker")):
        try:
            os.makedirs(base, exist_ok=True)
            return os.path.join(base, name)
        except OSError:
            continue
    return os.path.join(tempfile.gettempdir(), name)


def cached_download(name, url, max_age_hours):
    """Download url into the cache (re-used for max_age_hours). Returns a path or None."""
    path = cache_path(name)
    if os.path.exists(path) and time.time() - os.path.getmtime(path) < max_age_hours * 3600:
        return path
    status, body = http_get(url, timeout=300, headers={"Accept": "*/*"})
    if status == 200 and body:
        with open(path, "wb") as f:
            f.write(body)
        return path
    return path if os.path.exists(path) else None   # stale cache beats nothing


def ripestat(call, **params):
    params.setdefault("sourceapp", "ripe-ip-checker")
    url = RIPESTAT.format(call) + "?" + urllib.parse.urlencode(params)
    status, data = http_json(url, timeout=90)
    if status == 200 and isinstance(data, dict) and data.get("status") == "ok":
        return data.get("data") or {}
    return None


_as_names = {}


def as_name(asn):
    asn = str(asn).upper().replace("AS", "")
    if asn not in _as_names:
        d = ripestat("as-overview", resource=f"AS{asn}")
        _as_names[asn] = (d or {}).get("holder") or "?"
    return _as_names[asn]


# ---------------------------------------------------------------- RIPE Database

class WObj:
    """A RIPE Database object (list of (attribute, value) pairs)."""

    def __init__(self, otype, attrs):
        self.type = otype
        self.attrs = attrs
        self.start = self.end = None
        if otype == "inetnum" and attrs:
            try:
                a, b = [x.strip() for x in attrs[0][1].split("-")]
                self.start, self.end = ip2int(a), ip2int(b)
            except ValueError:
                pass

    def get(self, name, default=""):
        for k, v in self.attrs:
            if k == name:
                return v
        return default

    def getall(self, name):
        return [v for k, v in self.attrs if k == name]

    @property
    def key(self):
        return self.attrs[0][1] if self.attrs else ""

    @property
    def size(self):
        return (self.end - self.start + 1) if self.start is not None else 0

    @property
    def status(self):
        return self.get("status").upper()

    def cidr(self):
        if self.start is None:
            return self.key
        c = range_to_cidrs(int2ip(self.start), int2ip(self.end))
        return c[0] if len(c) == 1 else f"{c[0]} +{len(c) - 1} more"


def _parse_db_objects(data):
    out = []
    for o in ((data or {}).get("objects") or {}).get("object", []):
        attrs = [(a.get("name"), a.get("value", "")) for a in
                 (o.get("attributes") or {}).get("attribute", [])]
        out.append(WObj(o.get("type"), attrs))
    return out


def ripe_db_search(query, type_filter, flags):
    params = [("query-string", query), ("type-filter", type_filter), ("source", "RIPE")]
    params += [("flags", f) for f in flags]
    url = f"{RIPE_DB}/search.json?" + urllib.parse.urlencode(params)
    status, data = http_json(url, timeout=60)
    if status == 404:              # "no entries found"
        return [], None
    if status != 200:
        return [], f"RIPE DB query failed (HTTP {status})"
    return _parse_db_objects(data), None


def ripe_db_lookup(otype, key):
    url = f"{RIPE_DB}/ripe/{otype}/{urllib.parse.quote(key)}.json"
    status, data = http_json(url, timeout=60)
    objs = _parse_db_objects(data) if status == 200 else []
    return objs[0] if objs else None


def whois_query(host, query, timeout=25):
    try:
        with socket.create_connection((host, 43), timeout=timeout) as s:
            s.sendall((query + "\r\n").encode())
            chunks = []
            while True:
                buf = s.recv(65536)
                if not buf:
                    break
                chunks.append(buf)
        return b"".join(chunks).decode("utf-8", "replace"), None
    except OSError as e:
        return "", str(e)


def parse_rpsl(text):
    objs, cur = [], []
    for line in text.splitlines():
        if not line.strip():
            if cur:
                objs.append(cur)
                cur = []
            continue
        if line.startswith(("%", "#")):
            continue
        m = re.match(r"^([A-Za-z0-9-]+):\s*(.*)$", line)
        if m:
            cur.append((m.group(1).lower(), m.group(2).strip()))
        elif cur and line[:1] in (" ", "\t", "+"):
            cur[-1] = (cur[-1][0], cur[-1][1] + " " + line.strip())
    if cur:
        objs.append(cur)
    return [WObj(o[0][0], o) for o in objs if o]


# =====================================================================================
#  Report model (plain text)
# =====================================================================================

class Section:
    def __init__(self, report, number, title, question):
        self.report = report
        self.number = number
        self.title = title
        self.question = question
        self.lines = []
        self.findings = []
        self._sub = 0

    # ---- text building
    def text(self, txt="", indent=2, hang=0):
        if not txt:
            self.lines.append("")
            return
        wrapped = wrap(txt, WIDTH - indent - hang) or [""]
        self.lines.append(" " * indent + wrapped[0])
        self.lines.extend(" " * (indent + hang) + w for w in wrapped[1:])

    def sub(self, title):
        self._sub += 1
        head = f"{self.number}.{self._sub}  {title}"
        self.lines += ["", "  " + head, "  " + "-" * len(head)]

    def kv(self, key, value, indent=4):
        value = "-" if value in (None, "") else str(value)
        prefix = " " * indent + f"{key:<24}: "
        wrapped = wrap(value, WIDTH - len(prefix)) or ["-"]
        self.lines.append(prefix + wrapped[0])
        self.lines.extend(" " * len(prefix) + w for w in wrapped[1:])

    def table(self, headers, rows, indent=4, max_col=38, max_rows=40):
        if not rows:
            self.lines.append(" " * indent + "(none)")
            return
        extra = len(rows) - max_rows
        rows = rows[:max_rows]
        cells = [[str(c) for c in headers]] + [["-" if c in (None, "") else str(c) for c in r]
                                                for r in rows]
        cells = [[c if len(c) <= max_col else c[:max_col - 2] + ".." for c in r] for r in cells]
        widths = [max(len(r[i]) for r in cells) for i in range(len(headers))]
        fmt = lambda r: " " * indent + "  ".join(c.ljust(widths[i]) for i, c in enumerate(r)).rstrip()
        self.lines.append(fmt(cells[0]))
        self.lines.append(" " * indent + "  ".join("-" * w for w in widths))
        self.lines.extend(fmt(r) for r in cells[1:])
        if extra > 0:
            self.lines.append(" " * indent + f"... and {extra} more rows not shown")

    def finding(self, severity, message):
        self.findings.append((severity, message))
        self.report.findings.append((severity, self.number, self.title, message))
        tag = f"[{severity}]"
        prefix = "    " + tag.ljust(11)
        wrapped = wrap(message, WIDTH - len(prefix)) or [""]
        self.lines.append(prefix + wrapped[0])
        self.lines.extend(" " * len(prefix) + w for w in wrapped[1:])

    def render(self):
        bar = "=" * WIDTH
        out = ["", bar, f" {self.number}. {self.title.upper()}", f"    {self.question}", bar]
        return out + self.lines


class Report:
    def __init__(self, net, meta):
        self.net = net
        self.meta = meta
        self.sections = []
        self.findings = []

    def section(self, title, question):
        s = Section(self, len(self.sections) + 1, title, question)
        self.sections.append(s)
        return s

    def counts(self):
        return {s: sum(1 for f in self.findings if f[0] == s) for s in SEV_ORDER}

    def verdict(self):
        c = self.counts()
        if c[CRITICAL]:
            return "DO NOT BUY", "At least one blocking problem was found (see CRITICAL items)."
        if c[HIGH]:
            return "HIGH RISK", "Resolve every HIGH item with the seller BEFORE any payment."
        if c[MEDIUM]:
            return "MODERATE RISK", "Acceptable only if the MEDIUM items are explained or fixed."
        return "LOW RISK", "No significant problems found by the automated checks."

    def render(self):
        bar = "#" * WIDTH
        net = self.net
        n24 = max(1, net.num_addresses // 256)
        verdict, why = self.verdict()
        c = self.counts()
        out = [bar,
               "#" + " IP RANGE PRE-PURCHASE DUE-DILIGENCE REPORT  (RIPE NCC region)".center(WIDTH - 2) + "#",
               bar, ""]
        out.append(f"  Supernet checked : {net}   ({net.num_addresses:,} addresses = {n24} x /24)")
        out.append(f"  Range            : {net.network_address} - {net.broadcast_address}")
        out.append(f"  Generated        : {NOW.strftime('%Y-%m-%d %H:%M UTC')}")
        out.append(f"  Tool             : ripe_ip_checker.py v{VERSION}")
        for k, v in self.meta.items():
            out.append(f"  {k:<17}: {v}")
        out += ["", "-" * WIDTH, "  EXECUTIVE SUMMARY", "-" * WIDTH, ""]
        out.append(f"  OVERALL VERDICT  :  >>> {verdict} <<<")
        out.append(f"                      {why}")
        out.append("")
        out.append("  Findings         :  " + "  |  ".join(
            f"{c[s]} {s.lower()}" for s in (CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN)) + f"  |  {c[OK]} ok")
        out.append("")
        issues = sorted([f for f in self.findings if f[0] in (CRITICAL, HIGH, MEDIUM, LOW)],
                        key=lambda f: (SEV_ORDER.index(f[0]), f[1]))
        if issues:
            out.append("  Issues to resolve (most severe first):")
            out.append("")
            for i, (sev, num, title, msg) in enumerate(issues, 1):
                prefix = f"  {i:>3}. [{sev}]".ljust(17) + f"(sec.{num}) "
                wrapped = wrap(msg, WIDTH - len(prefix))
                out.append(prefix + wrapped[0])
                out.extend(" " * len(prefix) + w for w in wrapped[1:])
        else:
            out.append("  No issues found.")
        unknown = [f for f in self.findings if f[0] == UNKNOWN]
        if unknown:
            out += ["", "  Checks that could NOT be completed (result unknown - verify manually):", ""]
            for sev, num, title, msg in unknown:
                prefix = f"     - (sec.{num}) "
                wrapped = wrap(msg, WIDTH - len(prefix))
                out.append(prefix + wrapped[0])
                out.extend(" " * len(prefix) + w for w in wrapped[1:])
        out += ["",
                "  How to read the tags:",
                "     [CRITICAL] deal-breaker          [HIGH]  must be fixed before paying",
                "     [MEDIUM]   explain / negotiate   [LOW]   minor, note it",
                "     [UNKNOWN]  check failed          [INFO]  context only        [OK] passed"]
        for s in self.sections:
            out += s.render()
        out += ["", bar,
                "  DISCLAIMER: automated checks based on public data at the time of generation. They do not",
                "  replace legal due diligence, a signed contract, escrow, or RIPE NCC transfer approval.",
                bar, ""]
        return "\n".join(out)


class Ctx:
    """Data shared between sections for one supernet."""

    def __init__(self, net, args):
        self.net = net
        self.args = args
        self.start = int(net.network_address)
        self.end = int(net.broadcast_address)
        if net.prefixlen <= 24:
            all24 = list(net.subnets(new_prefix=24))
        else:
            all24 = [net]
        self.all24 = all24
        if len(all24) > MAX_24S:
            step = len(all24) / MAX_24S
            self.nets24 = [all24[int(i * step)] for i in range(MAX_24S)]
        else:
            self.nets24 = all24
        self.sample_ips = []            # (net24, ip)
        for n in self.nets24:
            hosts = range(n.num_addresses) if args.full_dnsbl else SAMPLE_OFFSETS
            for off in hosts:
                if off < n.num_addresses:
                    self.sample_ips.append((n, str(n[off])))
        self.api_ips = [str(n[1] if n.num_addresses > 1 else n[0])
                        for n in self.nets24][:API_SAMPLE_CAP]
        self.holders = []
        self.holder_orgs = {}           # org-handle -> WObj
        self.current_origins = set()
        self.all_origins = set()
        self.countries = {}             # source -> set(country codes)
        self.drop_listed = False


# =====================================================================================
#  1. Registry ownership & status
# =====================================================================================

def check_registry(rep, ctx):
    s = rep.section("Registry ownership & status",
                    "Is the range registered in RIPE NCC, who is the real holder, and can it be transferred?")
    net = ctx.net

    s.sub("Regional Internet Registry")
    rir = ripestat("rir", resource=str(net))
    rirs = sorted({r.get("rir", "?") for r in (rir or {}).get("rirs", [])})
    s.kv("Responsible RIR", ", ".join(rirs) or "unknown")
    if rir is None:
        s.finding(UNKNOWN, "Could not query RIR data (RIPEstat 'rir').")
    elif not rirs:
        s.finding(HIGH, "No RIR delegation found - the range may be unallocated / bogon space.")
    elif any("RIPE" not in r.upper() for r in rirs):
        s.finding(HIGH, f"Range (or part of it) is managed by {', '.join(rirs)}, not RIPE NCC. "
                        "An inter-RIR transfer is needed and the other RIR's policy applies.")
    else:
        s.finding(OK, "Range is administered by RIPE NCC.")

    less, err1 = ripe_db_search(str(net), "inetnum", ["L", "r"])
    more, err2 = ripe_db_search(str(net), "inetnum", ["M", "r"])
    for err in (err1, err2):
        if err:
            s.finding(UNKNOWN, err)
    seen, objs = set(), []
    for o in less + more:
        if o.start is not None and o.key not in seen:
            seen.add(o.key)
            objs.append(o)

    def is_registry_parent(o):
        return o.get("org") in REGISTRY_ORGS or o.get("netname") == "IANA-BLK" or \
            o.status == "ALLOCATED UNSPECIFIED"

    def is_holder(o):
        return o.status in HOLDER_STATUSES and o.get("org") not in REGISTRY_ORGS

    covering = sorted([o for o in objs if o.start <= ctx.start and o.end >= ctx.end
                       and not is_registry_parent(o)], key=lambda o: -o.size)
    inside = sorted([o for o in objs if o.start >= ctx.start and o.end <= ctx.end
                     and not (o.start == ctx.start and o.end == ctx.end)], key=lambda o: o.start)

    s.sub("Registration hierarchy (covering objects, largest first)")
    s.table(["Range", "CIDR", "Status", "Netname", "Org", "Created"],
            [[o.key, o.cidr(), o.status, o.get("netname"), o.get("org"),
              fmt_date(parse_dt(o.get("created")))] for o in covering])

    cands = [o for o in objs if is_holder(o)]
    holders = [o for o in cands if not any(p is not o and p.start <= o.start and o.end <= p.end
                                           and p.size > o.size for p in cands)]
    holders.sort(key=lambda o: o.start)
    ctx.holders = holders

    s.sub("Resource holder")
    if not holders:
        s.finding(CRITICAL, "No transferable RIPE registration (ALLOCATED PA / ASSIGNED PI / LEGACY) "
                            "covers this range. Nobody can legally transfer it to you through RIPE NCC.")
        return
    covered = sum(overlap_size(h.start, h.end, ctx.start, ctx.end) for h in holders)
    if covered < net.num_addresses:
        s.finding(HIGH, f"Only {covered:,} of {net.num_addresses:,} addresses are covered by a holder "
                        "registration. Part of the supernet belongs to nobody or to unrelated registrations.")
    if len(holders) > 1:
        s.finding(MEDIUM, f"The supernet spans {len(holders)} separate registrations. Each one is a "
                          "separate transfer, possibly from different holders.")

    for h in holders:
        org = ripe_db_lookup("organisation", h.get("org")) if h.get("org") else None
        if org:
            ctx.holder_orgs[h.get("org")] = org
        s.text("")
        s.kv("Holder block", f"{h.key}  ({h.cidr()}, {h.size:,} addresses)")
        s.kv("Status", h.status)
        s.kv("Netname", h.get("netname"))
        s.kv("Organisation handle", h.get("org"))
        if org:
            s.kv("Organisation name", org.get("org-name"))
            s.kv("Organisation type", org.get("org-type"))
            s.kv("Organisation country", org.get("country"))
            s.kv("Organisation address", ", ".join(org.getall("address")))
            s.kv("Organisation created", fmt_date(parse_dt(org.get("created"))))
        s.kv("Block country", h.get("country"))
        s.kv("Maintained by (mnt-by)", ", ".join(h.getall("mnt-by")))
        s.kv("Created", fmt_date(parse_dt(h.get("created"))))
        s.kv("Last modified", fmt_date(parse_dt(h.get("last-modified"))))
        s.text("")

        st, mnts = h.status, h.getall("mnt-by")
        org_type = (org.get("org-type") if org else "").upper()
        if st in ("ALLOCATED PA", "ALLOCATED-ASSIGNED PA"):
            s.finding(OK, "Status is a PA allocation - transferable under the RIPE transfer policy. "
                          "You (the recipient) must be a RIPE NCC member (LIR) to receive it.")
            if org and org_type != "LIR":
                s.finding(HIGH, f"PA allocation held by an organisation with org-type '{org_type or '?'}' "
                                "instead of LIR. Ask the seller and RIPE NCC to explain.")
            if "RIPE-NCC-HM-MNT" not in mnts:
                s.finding(MEDIUM, "Allocation is not locked by RIPE-NCC-HM-MNT as expected - verify registration.")
        elif st == "ASSIGNED PI":
            s.finding(OK, "Status is ASSIGNED PI - transferable. The recipient needs a sponsoring LIR "
                          "(or to be an LIR).")
            if "RIPE-NCC-END-MNT" not in mnts:
                s.finding(MEDIUM, "PI assignment is not locked by RIPE-NCC-END-MNT as expected - verify.")
        elif st == "LEGACY":
            s.finding(INFO, "LEGACY space - transferable, but check that the holder has a contract with "
                            "RIPE NCC (membership or sponsoring LIR). Legacy without a contract is harder "
                            "to transfer and has limited RIPE NCC services.")
        elif st == "ASSIGNED ANYCAST":
            s.finding(CRITICAL, "ASSIGNED ANYCAST space cannot be transferred.")
        else:
            s.finding(MEDIUM, f"Unusual holder status '{st}' - confirm with RIPE NCC that it is transferable.")

        created = parse_dt(h.get("created"))
        if created and (NOW - created).days < 730 and st.startswith("ALLOCATED"):
            s.finding(HIGH, f"Registry object created {fmt_date(created)} (less than 24 months ago). "
                            "This usually means the range was recently allocated or transferred, and RIPE "
                            "policy blocks re-transfer for 24 months. Earliest possible transfer: "
                            f"{fmt_date(add_months(created, 24))}. Confirm with section 2.")
        if h.size > net.num_addresses:
            pct = 100.0 * net.num_addresses / h.size
            s.finding(INFO, f"You are buying {pct:.1f}% of a larger block ({h.cidr()}). The seller keeps "
                            "the rest, so their future use of neighbouring space can affect your reputation.")

    # --- the "reseller" check: who appears on the most specific object?
    s.sub("Objects inside / below the holder (assignments, sub-allocations)")
    holder_orgs = {h.get("org") for h in holders}
    below = [o for o in covering if not is_holder(o)] + [o for o in inside if not is_holder(o)]
    exact = next((o for o in objs if o.start == ctx.start and o.end == ctx.end), None)
    s.table(["Range", "CIDR", "Status", "Netname", "Org", "Created"],
            [[o.key, o.cidr(), o.status, o.get("netname"), o.get("org") or "(none)",
              fmt_date(parse_dt(o.get("created")))] for o in below], max_rows=30)
    s.text("")
    if exact and not is_holder(exact) and exact.get("org") and exact.get("org") not in holder_orgs:
        s.finding(HIGH, f"The exact-match object ({exact.status}) names organisation {exact.get('org')}, "
                        f"which is NOT the holder ({', '.join(sorted(holder_orgs))}). If the seller is "
                        f"{exact.get('org')}, they are only a user of the space and CANNOT transfer it - "
                        "only the holder can.")
    foreign = sorted({o.get("org") for o in below if o.get("org") and o.get("org") not in holder_orgs})
    if foreign:
        s.finding(MEDIUM, f"Parts of the range are assigned to other organisations ({', '.join(foreign[:6])}). "
                          "These customers must be migrated off and the objects deleted before transfer.")
    if below:
        s.finding(LOW, f"{len(below)} assignment/sub-allocation object(s) exist. The seller must delete them "
                       "before RIPE NCC can process the transfer.")
    else:
        s.finding(OK, "No assignment objects below the holder - clean registration.")


# =====================================================================================
#  2. Transfer history
# =====================================================================================

def check_transfers(rep, ctx):
    s = rep.section("Transfer history",
                    "Has the range changed hands before, how often, and is it blocked by the 24-month rule?")
    s.sub("Registered transfers (RIPE NCC transfer statistics)")
    path = cached_download("transfers_latest.json", TRANSFERS_URL, 24)
    hits = []
    if not path:
        s.finding(UNKNOWN, "Could not download the RIPE NCC transfer statistics.")
    else:
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            data = {}
            s.finding(UNKNOWN, "RIPE NCC transfer statistics file could not be parsed.")
        for t in data.get("transfers", []):
            nets = t.get("ip4nets") or {}
            for rng in nets.get("transfer_set") or nets.get("original_set") or []:
                try:
                    a, b = ip2int(rng["start_address"]), ip2int(rng["end_address"])
                except (KeyError, ValueError):
                    continue
                if overlap_size(a, b, ctx.start, ctx.end):
                    hits.append((parse_dt(t.get("transfer_date")), t, a, b))
    hits.sort(key=lambda x: x[0] or NOW)
    rows = []
    for d, t, a, b in hits:
        so, ro = t.get("source_organization") or {}, t.get("recipient_organization") or {}
        party = lambda o: (o.get("name") or "?") + (f" ({o['country_code']})" if o.get("country_code") else "")
        rows.append([fmt_date(d), (t.get("type") or "").replace("_", " ").title(), party(so), party(ro),
                     ", ".join(range_to_cidrs(int2ip(a), int2ip(b))[:2]),
                     f"{t.get('source_rir', '?')}->{t.get('recipient_rir', '?')}"])
    s.table(["Date", "Type", "From", "To", "Range", "RIR"], rows, max_col=34)
    s.text("")

    if path and not hits:
        s.finding(OK, "No registered transfers found (never sold since RIPE NCC started publishing "
                      "transfer statistics in 2012).")
    last_rt = None
    for d, t, _, _ in hits:
        if d and (NOW - d).days < 730:
            if t.get("type") == "MERGER_ACQUISITION":
                s.finding(MEDIUM, f"Merger/acquisition transfer on {fmt_date(d)} (less than 24 months ago). "
                                  "Confirm with RIPE NCC whether the 24-month restriction applies.")
            else:
                last_rt = d
        if t.get("source_rir") and t.get("source_rir") != "RIPE NCC":
            s.finding(INFO, f"Inter-RIR transfer from {t.get('source_rir')} on {fmt_date(d)}. "
                            "Check the history in that RIR too.")
    if last_rt:
        s.finding(HIGH, f"Range was transferred on {fmt_date(last_rt)}. RIPE policy forbids re-transferring "
                        f"it for 24 months: earliest possible transfer is {fmt_date(add_months(last_rt, 24))}.")
    recent = [h for h in hits if h[0] and (NOW - h[0]).days < 5 * 365]
    if len(recent) >= 3:
        s.finding(MEDIUM, f"{len(recent)} transfers in the last 5 years - the range is traded frequently "
                          "(IP flipping). Ask why.")
    if hits and ctx.holder_orgs:
        last_to = norm_name((hits[-1][1].get("recipient_organization") or {}).get("name"))
        holder_names = [norm_name(o.get("org-name")) for o in ctx.holder_orgs.values()]
        if last_to and not any(last_to in h or h in last_to for h in holder_names if h):
            s.finding(MEDIUM, "The recipient of the latest transfer does not match the current holder "
                              "organisation name - check for later renames or unregistered changes.")

    # ---- registry object history
    s.sub("RIPE Database history of the holder object(s)")
    for h in ctx.holders[:3]:
        hist = ripestat("historical-whois", resource=h.key)
        if hist is None:
            s.finding(UNKNOWN, f"Could not fetch historical whois for {h.key}.")
            continue
        versions = sorted(hist.get("versions", []), key=lambda v: v.get("version", 0))
        s.kv("Object", h.key)
        s.kv("Versions recorded", f"{hist.get('num_versions', len(versions))} "
                                  f"(first {fmt_date(parse_dt(versions[0]['from_time'])) if versions else '-'})")

        def fetch_version(v):
            d = ripestat("historical-whois", resource=h.key, version=v["version"])
            for o in (d or {}).get("objects", []):
                attrs = {}
                for a in o.get("attributes", []):
                    attrs.setdefault(a.get("attribute"), []).append(a.get("value", ""))
                return v, attrs
            return v, None

        tracked = ("org", "status", "netname", "country", "mnt-by")
        snaps = [r for r in pmap(fetch_version, versions[-40:], workers=8)
                 if isinstance(r, tuple) and r[1]]
        rows, prev = [], None
        for v, attrs in snaps:
            cur = {k: ", ".join(attrs.get(k, [])) for k in tracked}
            if prev is None:
                rows.append([fmt_date(parse_dt(v["from_time"])), f"v{v['version']}", "first recorded state",
                             f"org={cur['org']} status={cur['status']}"])
            else:
                for k in tracked:
                    if cur[k] != prev[k]:
                        rows.append([fmt_date(parse_dt(v["from_time"])), f"v{v['version']}",
                                     f"{k} changed", f"{prev[k] or '(none)'} -> {cur[k] or '(none)'}"])
            prev = cur
        s.table(["Date", "Ver", "Change", "Details"], rows, max_col=60)
        s.text("")
        org_changes = sum(1 for r in rows if r[2] == "org changed")
        if org_changes >= 2:
            s.finding(MEDIUM, f"Holder organisation changed {org_changes} times on {h.key}.")
        elif org_changes == 1:
            s.finding(INFO, f"Holder organisation changed once on {h.key}.")


# =====================================================================================
#  3. BGP / routing history
# =====================================================================================

def check_bgp(rep, ctx):
    s = rep.section("BGP / routing history",
                    "Who announced this range, when, and is anything suspicious going on right now?")
    net = str(ctx.net)

    s.sub("Current routing status")
    rs = ripestat("routing-status", resource=net)
    if rs is None:
        s.finding(UNKNOWN, "Could not query RIPEstat routing-status.")
        rs = {}
    origins = [str(o.get("origin")) for o in rs.get("origins", [])]
    vis = (rs.get("visibility") or {}).get("v4") or {}
    more = rs.get("more_specifics") or []
    less = rs.get("less_specifics") or []

    def pfx_origin(item):
        if isinstance(item, dict):
            return item.get("prefix"), str(item.get("origin", "?"))
        return str(item), "?"

    more_po = [pfx_origin(m) for m in more]
    less_po = [pfx_origin(m) for m in less]
    ctx.current_origins = set(origins) | {o for _, o in more_po if o != "?"}
    announced_now = bool(origins or more_po)

    s.kv("Announced right now", "YES" if announced_now else "NO")
    for o in origins:
        s.kv("Origin AS (exact prefix)", f"AS{o}  {as_name(o)}")
    if vis.get("total_ris_peers"):
        s.kv("Visibility", f"{vis.get('ris_peers_seeing')} of {vis.get('total_ris_peers')} RIS peers")
    s.kv("First seen in BGP", f"{fmt_date(parse_dt((rs.get('first_seen') or {}).get('time')))} "
                              f"(origin AS{(rs.get('first_seen') or {}).get('origin', '?')})"
         if rs.get("first_seen") else "never")
    s.kv("Last seen in BGP", fmt_date(parse_dt((rs.get("last_seen") or {}).get("time")))
         if rs.get("last_seen") else "never")
    if more_po:
        s.text("")
        s.text("More-specific prefixes announced now:", 4)
        s.table(["Prefix", "Origin AS", "AS name"], [[p, f"AS{o}", as_name(o) if o != "?" else "?"]
                                                    for p, o in more_po], indent=6)
    if less_po:
        s.text("")
        s.text("Covering (less-specific) prefixes announced now:", 4)
        s.table(["Prefix", "Origin AS", "AS name"], [[p, f"AS{o}", as_name(o) if o != "?" else "?"]
                                                    for p, o in less_po], indent=6)
    s.text("")

    if len(set(origins)) > 1:
        s.finding(HIGH, f"MOAS: the prefix is announced by {len(set(origins))} different origin ASes at the "
                        "same time (" + ", ".join("AS" + o for o in origins) + "). Possible hijack or conflict.")
    if origins:
        s.finding(INFO, "Currently announced by " + ", ".join(f"AS{o} ({as_name(o)})" for o in origins) +
                  ". Confirm this AS belongs to the seller; the announcement must be withdrawn at handover.")
    if more_po:
        others = sorted({o for _, o in more_po if o not in origins})
        if others and origins:
            s.finding(MEDIUM, "Parts of the range are announced by other AS(es): " +
                      ", ".join(f"AS{o}" for o in others) + " - someone else is using this space (lease?).")
        elif more_po and not origins:
            s.finding(INFO, f"{len(more_po)} more-specific prefix(es) are announced (range is split / in use).")
    if vis.get("total_ris_peers") and announced_now and origins:
        ratio = vis.get("ris_peers_seeing", 0) / max(1, vis["total_ris_peers"])
        if ratio < 0.5:
            s.finding(MEDIUM, f"Low visibility: only {ratio:.0%} of RIS peers see the route - it is being "
                              "filtered (bad RPKI/IRR data or reputation).")
        else:
            s.finding(OK, f"Route is widely visible ({ratio:.0%} of RIS peers).")
    if not rs.get("first_seen") and not announced_now:
        s.finding(INFO, "Never seen in BGP - no routing baggage, but also no track record.")
    elif not announced_now:
        last = parse_dt((rs.get("last_seen") or {}).get("time"))
        s.finding(INFO, f"Not announced right now. Last seen in BGP on {fmt_date(last)}"
                        + (f" ({(NOW - last).days} days ago)" if last else "") +
                  " - check section 5 for any reputation damage from that period.")

    s.sub("Origin AS history (RIPE RIS, since 2000)")
    rh = ripestat("routing-history", resource=net)
    if rh is None:
        s.finding(UNKNOWN, "Could not query RIPEstat routing-history.")
        return
    rows, short, covering = [], [], []
    for bo in rh.get("by_origin", []):
        origin = str(bo.get("origin"))
        for p in bo.get("prefixes", []):
            tl = p.get("timelines", [])
            if not tl:
                continue
            try:
                pnet = ipaddress.ip_network(p.get("prefix"))
            except ValueError:
                continue
            if pnet.prefixlen < ctx.net.prefixlen:
                # a covering route (e.g. a leaked /8) - not an announcement of this range itself
                covering.append((origin, p.get("prefix"), tl))
                continue
            ctx.all_origins.add(origin)
            first = min(parse_dt(t["starttime"]) for t in tl)
            last = max(parse_dt(t["endtime"]) for t in tl)
            days = sum(max(1, (parse_dt(t["endtime"]) - parse_dt(t["starttime"])).days) for t in tl)
            peers = max(t.get("full_peers_seeing", 0) for t in tl)
            rows.append((first, [f"AS{origin}", as_name(origin), p.get("prefix"),
                                 fmt_date(first), fmt_date(last), days, f"{peers:.0f}"]))
            if days < 14 and origin not in ctx.current_origins:
                short.append(f"AS{origin} {p.get('prefix')} ({days}d, {fmt_date(first)})")
    rows.sort(key=lambda r: r[0])
    s.text("Announcements of this range or its sub-prefixes:", 4)
    s.table(["Origin", "AS name", "Prefix", "First seen", "Last seen", "Days", "Peers"],
            [r[1] for r in rows], max_col=30, indent=6)
    s.text("")
    if covering:
        crow = []
        for origin, pfx, tl in covering:
            first = min(parse_dt(t["starttime"]) for t in tl)
            last = max(parse_dt(t["endtime"]) for t in tl)
            crow.append((first, [f"AS{origin}", as_name(origin), pfx, fmt_date(first), fmt_date(last)]))
        crow.sort(key=lambda r: r[0])
        s.text("Covering (larger) routes that included this range - upstream aggregates or route leaks:", 4)
        s.table(["Origin", "AS name", "Prefix", "First seen", "Last seen"], [r[1] for r in crow],
                max_col=30, indent=6)
        s.text("")
    n_orig = len(ctx.all_origins)
    s.kv("Distinct origin ASes", n_orig)
    if n_orig >= 4:
        s.finding(MEDIUM, f"{n_orig} different origin ASes over time - the range has been passed around "
                          "(leasing/brokering). Check each AS in the table for reputation.")
    elif n_orig >= 2:
        s.finding(INFO, f"{n_orig} origin ASes over time - normal for ranges that were leased or moved.")
    elif n_orig == 1:
        s.finding(OK, "Only one origin AS in history - stable, single operator.")
    if short:
        s.finding(MEDIUM, "Short-lived announcements (<14 days) by non-current origins - typical of hijacks "
                          "or spam 'hit-and-run': " + "; ".join(short[:6]))


# =====================================================================================
#  4. RPKI & IRR
# =====================================================================================

def check_rpki_irr(rep, ctx):
    s = rep.section("RPKI (ROAs) & IRR route objects",
                    "Which ASes are authorised to announce the range, and is there stale data to clean up?")
    net = str(ctx.net)

    s.sub("ROAs covering the range")
    queries = [net] + ([str(n) for n in ctx.nets24] if len(ctx.nets24) > 1 else [])
    results = pmap(lambda p: ripestat("rpki-validation", resource="AS0", prefix=p), queries, workers=8)
    roas, failed = {}, 0
    for r in results:
        if not isinstance(r, dict):
            failed += 1
            continue
        for v in r.get("validating_roas", []):
            roas[(v.get("prefix"), str(v.get("origin")), v.get("max_length"))] = True
    if failed == len(results):
        s.finding(UNKNOWN, "Could not query RPKI data (RIPEstat rpki-validation).")
    rows = sorted(roas.keys(), key=lambda k: (ipaddress.ip_network(k[0]), k[1]))
    s.table(["ROA prefix", "Origin", "Max length", "AS name"],
            [[p, f"AS{o}", ml, "(do-not-route)" if o == "0" else as_name(o)] for p, o, ml in rows])
    s.text("")
    roa_origins = {o for _, o, _ in rows}
    if not rows:
        s.finding(INFO, "No ROAs exist. You will create your own after the transfer.")
    else:
        if roa_origins == {"0"}:
            s.finding(OK, "Only AS0 ROAs exist (holder has marked the space 'do not route' - good for parked space).")
        foreign = sorted(roa_origins - {"0"})
        if foreign:
            s.finding(LOW, "ROAs authorise " + ", ".join(f"AS{o}" for o in foreign) +
                      ". The seller must delete these at handover or those ASes can keep announcing your space.")

    s.sub("RPKI validity of the current announcements")
    announcements = []
    rs = ripestat("routing-status", resource=net) or {}
    for o in rs.get("origins", []):
        announcements.append((net, str(o.get("origin"))))
    for m in rs.get("more_specifics") or []:
        if isinstance(m, dict) and m.get("origin") is not None:
            announcements.append((m.get("prefix"), str(m.get("origin"))))
    if not announcements:
        s.text("Nothing is announced right now - nothing to validate.", 4)
    vrows, vres = [], []
    for p, o in announcements:
        v = ripestat("rpki-validation", resource=f"AS{o}", prefix=p)
        status = (v or {}).get("status", "unknown")
        vrows.append([p, f"AS{o}", status.upper()])
        vres.append((p, o, status))
    if vrows:
        s.table(["Prefix", "Origin", "RPKI status"], vrows)
        s.text("")
    for p, o, status in vres:
        if status.startswith("invalid"):
            s.finding(HIGH, f"{p} announced by AS{o} is RPKI {status.upper()}: the announcement is not "
                            "authorised by the holder (possible hijack) or the ROAs are wrong.")
        elif status == "valid":
            s.finding(OK, f"{p} announced by AS{o} is RPKI VALID.")

    s.sub(f"IRR route objects (all major IRRs via {IRR_WHOIS})")
    irr, errors = {}, []
    for flag in ("-x", "-M", "-L"):
        text, err = whois_query(IRR_WHOIS, f"-T route {flag} {net}")
        if err:
            errors.append(err)
            continue
        for o in parse_rpsl(text):
            if o.type != "route":
                continue
            route = o.get("route")
            try:
                if ipaddress.ip_network(route).prefixlen < 8:
                    continue
            except ValueError:
                continue
            src = o.get("source").split("#")[0].strip().upper()
            irr[(route, o.get("origin").upper(), src)] = fmt_date(parse_dt(o.get("last-modified")))
    if errors and not irr:
        s.finding(UNKNOWN, f"IRR whois query failed ({errors[0]}). Port 43 may be blocked.")
    rows = sorted(irr.items(), key=lambda kv: (ipaddress.ip_network(kv[0][0]), kv[0][2]))
    s.table(["Route", "Origin", "IRR source", "Last modified"],
            [[r, o, src, lm] for (r, o, src), lm in rows])
    s.text("")
    real = {k: v for k, v in irr.items() if k[2] != "RPKI"}
    non_ripe = sorted({k[2] for k in real if k[2] != "RIPE"})
    nonauth = [k for k in real if "NONAUTH" in k[2]]
    if nonauth:
        s.finding(MEDIUM, f"{len(nonauth)} route object(s) in NON-AUTHORITATIVE IRR databases "
                          f"({', '.join(sorted({k[2] for k in nonauth}))}). Anyone could have created them.")
    if non_ripe:
        s.finding(LOW, f"Route objects exist in third-party IRRs ({', '.join(non_ripe)}). Ask the seller to "
                       "delete them; stale objects let other networks announce your space.")
    irr_origins = sorted({k[1] for k in real})
    if irr_origins:
        s.finding(INFO, "IRR route objects authorise: " + ", ".join(irr_origins) +
                  ". All of them must be removed/replaced at handover.")
    elif not errors:
        s.finding(OK, "No IRR route objects found.")


# =====================================================================================
#  5. IP reputation
# =====================================================================================

DNSBLS = [
    # (display name, zone, severity when listed)
    ("Spamhaus ZEN", "zen.spamhaus.org", None),          # decoded separately
    ("Barracuda", "b.barracudacentral.org", MEDIUM),
    ("SpamCop", "bl.spamcop.net", MEDIUM),
    ("UCEPROTECT L1 (IP)", "dnsbl-1.uceprotect.net", LOW),
    ("UCEPROTECT L2 (netblock)", "dnsbl-2.uceprotect.net", MEDIUM),
    ("UCEPROTECT L3 (ASN)", "dnsbl-3.uceprotect.net", MEDIUM),
    ("PSBL", "psbl.surriel.com", LOW),
    ("Mailspike", "bl.mailspike.net", LOW),
    ("DroneBL", "dnsbl.dronebl.org", MEDIUM),
    ("s5h", "all.s5h.net", LOW),
]
ZEN_CODES = {
    "127.0.0.2": ("SBL", HIGH), "127.0.0.3": ("CSS", HIGH),
    "127.0.0.4": ("XBL", MEDIUM), "127.0.0.5": ("XBL", MEDIUM), "127.0.0.6": ("XBL", MEDIUM),
    "127.0.0.7": ("XBL", MEDIUM), "127.0.0.9": ("DROP", CRITICAL),
    "127.0.0.10": ("PBL", INFO), "127.0.0.11": ("PBL", INFO),
}


def dnsbl_lookup(ip, zone):
    q = ".".join(reversed(ip.split("."))) + "." + zone
    try:
        return socket.gethostbyname_ex(q)[2]
    except (socket.gaierror, socket.herror, UnicodeError, OSError):
        return []


def load_netset(name, url, hours):
    path = cached_download(name, url, hours)
    if not path:
        return None
    nets = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                n = ipaddress.ip_network(line.split()[0], strict=False)
            except ValueError:
                continue
            if n.version == 4:
                nets.append((int(n.network_address), int(n.broadcast_address), str(n)))
    return nets


def check_reputation(rep, ctx):
    s = rep.section("IP reputation",
                    "Is the range (or its neighbourhood) listed as a source of spam, attacks or fraud?")
    net = ctx.net

    # ---- 5.1 Spamhaus DROP
    s.sub("Spamhaus DROP (hijacked / criminal-controlled networks)")
    path = cached_download("drop_v4.json", DROP_URL, 6)
    if not path:
        s.finding(UNKNOWN, "Could not download the Spamhaus DROP list.")
    else:
        hits = []
        with open(path, encoding="utf-8") as f:
            for line in f:
                try:
                    e = json.loads(line)
                except ValueError:
                    continue
                if "cidr" not in e:
                    continue
                n = ipaddress.ip_network(e["cidr"], strict=False)
                if n.overlaps(net):
                    hits.append([e["cidr"], e.get("sblid", "-"), e.get("rir", "-")])
        s.table(["Listed CIDR", "SBL id", "RIR"], hits)
        s.text("")
        ctx.drop_listed = bool(hits)
        if hits:
            s.finding(CRITICAL, f"Range overlaps Spamhaus DROP ({', '.join(h[0] for h in hits)}). DROP means "
                                "hijacked or criminal-controlled space; most networks null-route it. Do not buy.")
        else:
            s.finding(OK, "Not on Spamhaus DROP.")

    # ---- 5.2 DNSBLs
    mode = "every IP" if ctx.args.full_dnsbl else f"{len(SAMPLE_OFFSETS)} sample IPs per /24 (.{', .'.join(map(str, SAMPLE_OFFSETS))})"
    s.sub(f"Email / DNS blocklists ({mode})")
    lists = list(DNSBLS)
    dqs = os.environ.get("SPAMHAUS_DQS_KEY")
    if dqs:
        lists[0] = ("Spamhaus ZEN (DQS)", f"{dqs}.zen.dq.spamhaus.net", None)
    tests = pmap(lambda l: dnsbl_lookup("127.0.0.2", l[1]), lists)
    working = [l for l, t in zip(lists, tests) if isinstance(t, list) and t
               and not any(a.startswith("127.255.255.") for a in t)]
    broken = [l for l in lists if l not in working]
    jobs = [(n24, ip, l) for (n24, ip) in ctx.sample_ips for l in working]
    log(f"DNSBL: {len(jobs)} lookups on {len(working)} lists ...")
    answers = pmap(lambda j: dnsbl_lookup(j[1], j[2][1]), jobs, workers=64)
    per24 = {}     # net24 -> {list name -> set(ips)}
    per_list = {}  # list name -> set(net24)
    zen_hits = {}  # code name -> (severity, set(ips))
    by_zone = {}   # list display name -> set(net24), for the status table
    for (n24, ip, l), ans in zip(jobs, answers):
        if not isinstance(ans, list) or not ans or any(a.startswith("127.255.255.") for a in ans):
            continue
        label = l[0]
        if l[2] is None:
            codes = sorted({ZEN_CODES.get(a, ("?", MEDIUM))[0] for a in ans})
            for a in ans:
                name, sev = ZEN_CODES.get(a, ("?", MEDIUM))
                zen_hits.setdefault(name, (sev, set()))[1].add(ip)
            if codes == ["PBL"]:
                continue     # PBL = "end-user range" policy list, not a bad-reputation listing
            label = f"Spamhaus {'/'.join(c for c in codes if c != 'PBL')}"
        per24.setdefault(n24, {}).setdefault(label, set()).add(ip)
        per_list.setdefault(label, set()).add(n24)
        by_zone.setdefault(l[0], set()).add(n24)
    s.table(["List", "Status", "/24s with listed IPs"],
            [[l[0], "working" if l in working else "UNAVAILABLE",
              len(by_zone.get(l[0], ())) if l in working else "-"] for l in lists])
    s.text("")
    for l in broken:
        extra = " Set SPAMHAUS_DQS_KEY or use your own recursive resolver." if "spamhaus" in l[1] else ""
        s.finding(UNKNOWN, f"{l[0]} did not answer its self-test (query refused or blocked by your DNS "
                           f"resolver) - result unknown.{extra}")
    if per24:
        s.text("Listed IPs per /24:", 4)
        sampled = {}
        for n24, _ in ctx.sample_ips:
            sampled[n24] = sampled.get(n24, 0) + 1
        rows = []
        for n, d in sorted(per24.items(), key=lambda kv: kv[0]):
            ips = sorted({ip for v in d.values() for ip in v}, key=ip2int)
            rows.append([str(n), ", ".join(sorted(d)), f"{len(ips)} of {sampled.get(n, len(ips))}",
                         ", ".join("." + ip.rsplit(".", 1)[1] for ip in ips[:6]) +
                         (" ..." if len(ips) > 6 else "")])
        s.table(["/24", "Listed on", "Listed", "Last octets"], rows, indent=6, max_col=60)
        s.text("")
    for name, (sev, ips) in sorted(zen_hits.items(), key=lambda kv: SEV_ORDER.index(kv[1][0])):
        if name == "DROP" and ctx.drop_listed:
            continue     # already reported from the DROP list itself (5.1)
        if name == "PBL":
            s.finding(INFO, f"{len(ips)} IP(s) on Spamhaus PBL (marked as end-user/dynamic space by the "
                            "current operator). Not a bad reputation; the new holder can remove it.")
        else:
            s.finding(sev, f"Spamhaus {name}: {len(ips)} sampled IP(s) listed "
                           f"(e.g. {', '.join(sorted(ips, key=ip2int)[:4])}).")
    n24_total = len(ctx.nets24)
    for l in working:
        if l[2] is None:
            continue
        affected = per_list.get(l[0], set())
        if not affected:
            continue
        frac = len(affected) / n24_total
        sev = l[2] if frac >= 0.25 else LOW
        if "L3" in l[0]:
            msg = (f"{l[0]}: the ASN currently announcing the range is listed. This follows the operator, "
                   "not the range - it clears once you announce it from your own ASN.")
        elif "L2" in l[0]:
            msg = (f"{l[0]}: {len(affected)} of {n24_total} /24s listed because of abuse from the netblock "
                   "as a whole (the current operator's network).")
        else:
            msg = f"{l[0]}: listed IPs in {len(affected)} of {n24_total} /24s ({frac:.0%})."
        s.finding(sev, msg)
    if working and not per24 and not any(n != "PBL" for n in zen_hits):
        s.finding(OK, f"No listings on the {len(working)} working DNS blocklists.")

    # ---- 5.3 FireHOL + Tor
    s.sub("Threat-intelligence aggregates (FireHOL) and Tor exit nodes")
    rows, pending = [], []
    for fname, sev, desc in FIREHOL_LISTS:
        nets = load_netset(fname, FIREHOL_BASE + fname, 6)
        if nets is None:
            rows.append([fname, "UNAVAILABLE", "-", desc])
            s.finding(UNKNOWN, f"Could not download {fname}.")
            continue
        hit = [(a, b, c) for a, b, c in nets if overlap_size(a, b, ctx.start, ctx.end)]
        addr = sum(overlap_size(a, b, ctx.start, ctx.end) for a, b, _ in hit)
        rows.append([fname.replace(".netset", ""), f"{addr} IPs" if hit else "clean",
                     ", ".join(c for _, _, c in hit[:3]) + (" ..." if len(hit) > 3 else ""), desc])
        if hit:
            pending.append((sev, f"FireHOL {fname.replace('.netset', '')}: {addr} address(es) listed "
                                 f"({', '.join(c for _, _, c in hit[:4])})."))
    tor = load_netset("tor_exits.txt", TOR_URL, 6)
    tor_hits = [c for a, b, c in (tor or []) if overlap_size(a, b, ctx.start, ctx.end)]
    rows.append(["tor exit nodes", "UNAVAILABLE" if tor is None else (f"{len(tor_hits)} IPs" if tor_hits else "clean"),
                 ", ".join(tor_hits[:3]), "Current Tor exit relays"])
    s.table(["List", "Result", "Matches", "Meaning"], rows, max_col=52)
    s.text("")
    for sev, msg in pending:
        if ctx.drop_listed and "level1" in msg:
            sev = INFO   # level1 includes DROP - already reported as CRITICAL in 5.1
        s.finding(sev, msg)
    if tor_hits:
        s.finding(MEDIUM, f"{len(tor_hits)} current Tor exit node(s) in the range - these IPs are blocked by "
                          "many services and will stay on reputation lists for a while.")
    if all(r[1] == "clean" for r in rows):
        s.finding(OK, "Not present in FireHOL threat lists or the Tor exit list.")

    # ---- 5.4 Optional APIs
    s.sub("Abuse reports, fraud scoring & scanner activity (optional API services)")
    check_abuseipdb(s, ctx)
    check_ipqs(s, ctx)
    check_otx(s, ctx)
    check_greynoise(s, ctx)

    s.sub("Manual look-ups (no public API)")
    ip = ctx.api_ips[0] if ctx.api_ips else str(net.network_address)
    s.kv("Cisco Talos", f"https://talosintelligence.com/reputation_center/lookup?search={ip}")
    s.kv("Spamhaus (full)", f"https://check.spamhaus.org/results/?query={ip}")
    s.kv("MXToolbox blacklists", f"https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a{ip}")
    s.kv("Microsoft SNDS / Google", "Postmaster tools - only available once you control the IPs")


def check_abuseipdb(s, ctx):
    key = os.environ.get("ABUSEIPDB_API_KEY")
    if not key:
        s.kv("AbuseIPDB", "SKIPPED - set ABUSEIPDB_API_KEY to enable")
        return
    nets = ctx.nets24[:25]

    def q(n):
        url = "https://api.abuseipdb.com/api/v2/check-block?" + urllib.parse.urlencode(
            {"network": str(n), "maxAgeInDays": 365})
        return http_json(url, headers={"Key": key})
    res = pmap(q, nets, workers=4)
    rows, worst, reported = [], 0, 0
    for n, r in zip(nets, res):
        if not isinstance(r, tuple) or r[0] != 200:
            rows.append([str(n), "error", "-", "-"])
            continue
        addrs = ((r[1] or {}).get("data") or {}).get("reportedAddress", [])
        top = max((a.get("abuseConfidenceScore", 0) for a in addrs), default=0)
        worst = max(worst, top)
        reported += len(addrs)
        last = max((a.get("mostRecentReport") or "" for a in addrs), default="")
        rows.append([str(n), len(addrs), top, fmt_date(parse_dt(last)) if last else "-"])
    s.text("AbuseIPDB (reports in the last 365 days):", 4)
    s.table(["/24", "Reported IPs", "Max confidence %", "Latest report"], rows, indent=6)
    s.text("")
    if len(ctx.nets24) > 25:
        s.finding(INFO, "AbuseIPDB checked only the first 25 /24s (free-tier limit).")
    if worst >= 75:
        s.finding(HIGH, f"AbuseIPDB: IPs with abuse confidence up to {worst}% ({reported} reported IPs).")
    elif worst >= 25:
        s.finding(MEDIUM, f"AbuseIPDB: {reported} reported IPs, max confidence {worst}%.")
    elif reported:
        s.finding(LOW, f"AbuseIPDB: {reported} IPs with low-confidence reports.")
    else:
        s.finding(OK, "AbuseIPDB: no abuse reports in the last 365 days.")


def check_ipqs(s, ctx):
    key = os.environ.get("IPQS_API_KEY")
    if not key:
        s.kv("IPQualityScore", "SKIPPED - set IPQS_API_KEY to enable")
        return
    res = pmap(lambda ip: http_json(f"https://ipqualityscore.com/api/json/ip/{key}/{ip}?strictness=0"),
               ctx.api_ips, workers=4)
    rows, scores, flags = [], [], set()
    for ip, r in zip(ctx.api_ips, res):
        d = r[1] if isinstance(r, tuple) and isinstance(r[1], dict) and r[1].get("success") else None
        if not d:
            rows.append([ip, "error", "", "", ""])
            continue
        fl = [k for k in ("proxy", "vpn", "tor", "recent_abuse", "bot_status") if d.get(k)]
        flags.update(fl)
        scores.append(d.get("fraud_score", 0))
        rows.append([ip, d.get("fraud_score"), ", ".join(fl) or "-", d.get("connection_type"), d.get("ISP")])
    s.text("IPQualityScore (one IP per /24):", 4)
    s.table(["IP", "Fraud score", "Flags", "Connection", "ISP"], rows, indent=6)
    s.text("")
    if scores and max(scores) >= 85:
        s.finding(HIGH, f"IPQualityScore fraud score up to {max(scores)} (85+ = high risk).")
    elif scores and max(scores) >= 75:
        s.finding(MEDIUM, f"IPQualityScore fraud score up to {max(scores)} (75+ = suspicious).")
    elif scores:
        s.finding(OK, f"IPQualityScore fraud scores are low (max {max(scores)}).")
    if flags & {"proxy", "vpn", "tor"}:
        s.finding(MEDIUM, "IPQualityScore classifies sampled IPs as " + "/".join(sorted(flags & {"proxy", "vpn", "tor"})) +
                  ". Streaming and banking services may block them until the classification is updated.")


def check_otx(s, ctx):
    key = os.environ.get("OTX_API_KEY")
    if not key:
        s.kv("AlienVault OTX", "SKIPPED - set OTX_API_KEY to enable")
        return
    res = pmap(lambda ip: http_json(f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
                                    headers={"X-OTX-API-KEY": key}), ctx.api_ips, workers=4)
    rows, total = [], 0
    for ip, r in zip(ctx.api_ips, res):
        if not isinstance(r, tuple) or r[0] != 200:
            rows.append([ip, "error"])
            continue
        c = ((r[1] or {}).get("pulse_info") or {}).get("count", 0)
        total += c
        rows.append([ip, c])
    s.text("AlienVault OTX threat pulses (one IP per /24):", 4)
    s.table(["IP", "Pulses"], rows, indent=6)
    s.text("")
    if total:
        s.finding(MEDIUM, f"AlienVault OTX: sampled IPs appear in {total} threat-intel pulse(s).")
    else:
        s.finding(OK, "AlienVault OTX: sampled IPs are not in any threat pulse.")


def check_greynoise(s, ctx):
    key = os.environ.get("GREYNOISE_API_KEY")
    ips = ctx.api_ips[: (API_SAMPLE_CAP if key else 10)]
    hdr = {"key": key} if key else {}
    res = pmap(lambda ip: http_json(f"https://api.greynoise.io/v3/community/{ip}", headers=hdr), ips, workers=4)
    rows, bad, errors = [], [], 0
    for ip, r in zip(ips, res):
        if not isinstance(r, tuple) or r[0] not in (200, 404) or not isinstance(r[1], dict):
            errors += 1
            rows.append([ip, "error / rate limited", "", ""])
            continue
        d = r[1]
        cls = d.get("classification") or ("not observed" if not d.get("noise") else "unknown")
        rows.append([ip, cls, "yes" if d.get("noise") else "no", d.get("name") or "-"])
        if cls == "malicious":
            bad.append(ip)
    s.text(f"GreyNoise internet-scanner activity ({len(ips)} sampled IPs{'' if key else ', no API key'}):", 4)
    s.table(["IP", "Classification", "Scanning", "Actor"], rows, indent=6)
    s.text("")
    if errors == len(ips):
        s.finding(UNKNOWN, "GreyNoise did not answer (rate limit or network).")
    elif bad:
        s.finding(MEDIUM, f"GreyNoise classifies {len(bad)} sampled IP(s) as MALICIOUS scanners: "
                          f"{', '.join(bad[:5])}.")
    else:
        s.finding(OK, "GreyNoise: no malicious scanning seen from the sampled IPs.")


# =====================================================================================
#  6. Geolocation
# =====================================================================================

def check_geo(rep, ctx):
    s = rep.section("Geolocation",
                    "Where do the major geolocation databases place the range, and is it consistent?")
    net = str(ctx.net)

    s.sub("Registry data (RIPE Database)")
    reg = set()
    for h in ctx.holders:
        if h.get("country"):
            reg.add(h.get("country").upper())
        for g in h.getall("geoloc"):
            s.kv("geoloc attribute", g)
        for g in h.getall("geofeed"):
            s.kv("geofeed attribute", g)
    for o in ctx.holder_orgs.values():
        s.kv(f"Holder org country", f"{o.get('country') or '-'}  ({o.get('org-name')})")
    s.kv("Block country", ", ".join(sorted(reg)) or "-")
    ctx.countries["RIPE DB"] = reg

    s.sub("MaxMind GeoLite2 (via RIPEstat)")
    g = ripestat("maxmind-geo-lite", resource=net)
    mm, rows = set(), []
    if g is None:
        s.finding(UNKNOWN, "Could not query MaxMind GeoLite data.")
    else:
        for lr in g.get("located_resources", []):
            for loc in lr.get("locations", []):
                if loc.get("country"):
                    mm.add(loc["country"].upper())
                rows.append([loc.get("country") or "?", loc.get("city") or "-",
                             f"{loc.get('covered_percentage', 0):.1f}%",
                             ", ".join(loc.get("resources", [])[:3])])
        s.table(["Country", "City", "Share", "Blocks"], rows)
        s.kv("Unknown share", f"{(g.get('unknown_percentage') or {}).get('v4', 0)}%")
    ctx.countries["MaxMind"] = mm

    s.sub("ipinfo.io (one IP per /24)")
    token = os.environ.get("IPINFO_TOKEN")
    ips = ctx.api_ips[: (API_SAMPLE_CAP if token else 10)]
    q = f"?token={token}" if token else ""
    res = pmap(lambda ip: http_json(f"https://ipinfo.io/{ip}/json{q}"), ips, workers=4)
    ii, rows = set(), []
    for ip, r in zip(ips, res):
        d = r[1] if isinstance(r, tuple) and r[0] == 200 and isinstance(r[1], dict) else None
        if not d:
            rows.append([ip, "error", "", "", ""])
            continue
        if d.get("country"):
            ii.add(d["country"].upper())
        priv = d.get("privacy") or {}
        pflags = ", ".join(k for k in ("vpn", "proxy", "tor", "hosting") if priv.get(k)) or "-"
        rows.append([ip, d.get("country", "-"), d.get("city", "-"), d.get("org", "-"), pflags])
    s.table(["IP", "Country", "City", "Org (current ASN)", "Privacy flags"], rows)
    s.text("")
    if rows and all(r[1] == "error" for r in rows):
        s.finding(UNKNOWN, "ipinfo.io did not answer (rate limit or network). Set IPINFO_TOKEN.")
    ctx.countries["ipinfo"] = ii

    all_cc = set().union(*ctx.countries.values()) - {"EU", "ZZ", ""}
    s.kv("Countries seen (all sources)", ", ".join(sorted(all_cc)) or "-")
    s.text("")
    risky = sorted(all_cc & set(HIGH_RISK_COUNTRIES))
    if risky:
        s.finding(HIGH, "Range is registered/geolocated in a sanctioned or high-risk country: " +
                  ", ".join(f"{c} ({HIGH_RISK_COUNTRIES[c]})" for c in risky) +
                  ". Many services block these countries and fixing geolocation takes weeks.")
    if len(all_cc) > 1:
        s.finding(MEDIUM, f"Geolocation is inconsistent across sources ({', '.join(sorted(all_cc))}). "
                          "Plan to publish a geofeed (RFC 8805) and file corrections after the transfer.")
    elif len(all_cc) == 1:
        s.finding(OK, f"All sources agree on the country: {next(iter(all_cc))}.")


# =====================================================================================
#  7. Past usage fingerprints
# =====================================================================================

PTR_PATTERNS = [
    ("residential/dynamic", r"(dyn|dynamic|pool|dsl|adsl|vdsl|cable|ppp|dhcp|broadband|cust|client|"
                            r"subscriber|home|ftth|fttx|gpon|res\b|residential|mobile|lte|wimax|wifi|wlan)"),
    ("hosting/server", r"(vps|server|srv|host|cloud|dedi|colo|static|mail|smtp|mx\d|ns\d|web|www)"),
]


def classify_ptr(name):
    for label, pat in PTR_PATTERNS:
        if re.search(pat, name.lower()):
            return label
    return "other"


def check_past_usage(rep, ctx):
    s = rep.section("Past-usage fingerprints",
                    "What was this space used for before (reverse DNS, PTR names, exposed services)?")
    net = str(ctx.net)

    s.sub("Reverse-DNS delegations (domain objects in RIPE DB)")
    rd = ripestat("reverse-dns", resource=net)
    rows = []
    if rd is None:
        s.finding(UNKNOWN, "Could not query reverse-DNS delegations.")
    else:
        for d in rd.get("delegations", []):
            kv = {}
            for a in d:
                kv.setdefault(a.get("key"), []).append(a.get("value"))
            rows.append([(kv.get("domain") or ["?"])[0], ", ".join(kv.get("nserver", []))[:60],
                         fmt_date(parse_dt((kv.get("last-modified") or [""])[0]))])
        # RIPEstat also returns delegations of covering zones; keep only the ones inside the supernet
        inside = [r for r in rows if _rdns_inside(r[0], ctx)]
        s.table(["Zone", "Name servers", "Last modified"], inside, max_col=60)
        s.text("")
        if inside:
            s.finding(LOW, f"{len(inside)} reverse-DNS delegation(s) exist. The seller must delete them so you "
                           "can create your own.")
        else:
            s.finding(OK, "No reverse-DNS delegations to clean up.")

    s.sub("PTR record sample (current reverse DNS names)")
    ips = [ip for _, ip in ctx.sample_ips][: 5 * API_SAMPLE_CAP * 2]

    def ptr(ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror, OSError):
            return None
    names = pmap(ptr, ips, workers=32)
    found = [(ip, n) for ip, n in zip(ips, names) if isinstance(n, str) and n]
    s.kv("IPs sampled", len(ips))
    s.kv("IPs with a PTR record", len(found))
    s.table(["IP", "PTR name", "Looks like"], [[ip, n, classify_ptr(n)] for ip, n in found], max_rows=25, max_col=60)
    s.text("")
    classes = {}
    for _, n in found:
        classes[classify_ptr(n)] = classes.get(classify_ptr(n), 0) + 1
    if classes.get("residential/dynamic"):
        s.finding(INFO, f"{classes['residential/dynamic']} PTR name(s) look residential/dynamic - the space was "
                        "used for end-users; expect PBL-style listings and 'residential' classification.")
    if classes.get("hosting/server"):
        s.finding(INFO, f"{classes['hosting/server']} PTR name(s) look like hosting/servers.")

    s.sub("Abuse contact and exposed services")
    ab = ripestat("abuse-contact-finder", resource=net)
    s.kv("Abuse contact", ", ".join((ab or {}).get("abuse_contacts", [])) or "none registered")
    if ab is not None and not ab.get("abuse_contacts"):
        s.finding(LOW, "No abuse contact registered - sign of poor maintenance.")
    key = os.environ.get("SHODAN_API_KEY")
    if not key:
        s.kv("Shodan", "SKIPPED - set SHODAN_API_KEY to enable")
    else:
        st, d = http_json("https://api.shodan.io/shodan/host/count?" + urllib.parse.urlencode(
            {"key": key, "query": f"net:{net}", "facets": "port:8,product:8"}))
        if st == 200 and isinstance(d, dict):
            s.kv("Shodan hosts found", d.get("total", 0))
            facets = d.get("facets") or {}
            s.kv("Top ports", ", ".join(f"{f['value']}({f['count']})" for f in facets.get("port", [])))
            s.kv("Top products", ", ".join(f"{f['value']}({f['count']})" for f in facets.get("product", [])))
        else:
            s.finding(UNKNOWN, f"Shodan query failed (HTTP {st}).")
    s.kv("Passive DNS (manual)", f"https://securitytrails.com/list/ip/{ctx.api_ips[0] if ctx.api_ips else net}")


def _rdns_inside(zone, ctx):
    """True if an in-addr.arpa zone name lies within the supernet."""
    labels = zone.lower().replace(".in-addr.arpa", "").rstrip(".").split(".")
    labels = [l.split("-")[0] for l in reversed(labels)]    # handle RFC 2317 style "0-25"
    try:
        octets = [int(x) for x in labels]
    except ValueError:
        return False
    plen = 8 * len(octets)
    octets += [0] * (4 - len(octets))
    zn = ipaddress.ip_network(f"{'.'.join(map(str, octets))}/{plen}", strict=False)
    return zn.subnet_of(ctx.net) if zn.prefixlen >= ctx.net.prefixlen else False


# =====================================================================================
#  8. Legal & compliance
# =====================================================================================

def check_legal(rep, ctx):
    s = rep.section("Legal & compliance",
                    "Is the seller who they say they are, and is the deal legally clean?")
    s.sub("Registered holder(s) - the seller's contract must be signed by this entity")
    if not ctx.holder_orgs:
        s.finding(UNKNOWN, "Holder organisation could not be determined (see section 1).")
    for handle, o in ctx.holder_orgs.items():
        s.kv("Organisation", f"{o.get('org-name')}  ({handle})")
        s.kv("Type / country", f"{o.get('org-type')} / {o.get('country') or '-'}")
        s.kv("Address", ", ".join(o.getall("address")))
        s.text("")
        cc = (o.get("country") or "").upper()
        if cc in HIGH_RISK_COUNTRIES:
            s.finding(HIGH, f"Holder is based in {HIGH_RISK_COUNTRIES[cc]}. Full sanctions screening (EU, "
                            "OFAC, UK) of the company and its owners is required; RIPE NCC freezes "
                            "resources of sanctioned parties.")
        check_opensanctions(s, o.get("org-name"), cc)

    s.sub("Manual checklist (cannot be automated - tick each one before paying)")
    items = [
        "Seller's legal entity == RIPE DB holder organisation above (company registry extract).",
        "If you deal with a broker/reseller: written mandate from the holder to sell THIS range.",
        "Holder is in good standing with RIPE NCC (no unpaid fees, no open investigation / deregistration).",
        "No court order, dispute or lien on the resources; no pending closure of the holder's LIR account.",
        "Company and ultimate beneficial owners screened against EU / OFAC / UK / UN sanctions lists.",
        "You (or your sponsoring LIR) are ready to receive: LIR membership, transfer fee budget.",
        "Contract: price per IP, reputation warranty (refund/delisting help for N days), handover of "
        "ROAs, route objects, rDNS and geofeed.",
        "Payment through escrow, released only after RIPE NCC approves the transfer and the RIPE DB "
        "shows you as holder.",
        "Seller withdraws BGP announcements and deletes ROAs / route objects / domain objects on the "
        "agreed date.",
    ]
    for it in items:
        s.text("[ ] " + it, 4, hang=4)


def check_opensanctions(s, name, cc):
    key = os.environ.get("OPENSANCTIONS_API_KEY")
    if not key:
        s.kv("Sanctions screening", "SKIPPED - set OPENSANCTIONS_API_KEY for automatic screening; "
                                    "otherwise check https://www.opensanctions.org manually")
        return
    body = {"queries": {"q1": {"schema": "Company", "properties": {"name": [name]}}}}
    if cc:
        body["queries"]["q1"]["properties"]["country"] = [cc.lower()]
    st, d = http_json("https://api.opensanctions.org/match/default", data=json.dumps(body).encode(),
                      headers={"Authorization": f"ApiKey {key}", "Content-Type": "application/json"})
    if st != 200 or not isinstance(d, dict):
        s.finding(UNKNOWN, f"OpenSanctions query failed (HTTP {st}).")
        return
    results = ((d.get("responses") or {}).get("q1") or {}).get("results", [])
    strong = [r for r in results if r.get("match")]
    close = [r for r in results if not r.get("match") and r.get("score", 0) >= 0.7]
    for r in (strong + close)[:5]:
        s.kv("  possible match", f"{r.get('caption')} (score {r.get('score', 0):.2f}, "
                                 f"{', '.join(r.get('datasets', [])[:3])})")
    if strong:
        s.finding(CRITICAL, f"OpenSanctions: '{name}' matches a sanctioned / listed entity.")
    elif close:
        s.finding(HIGH, f"OpenSanctions: '{name}' has close (unconfirmed) matches - review manually.")
    else:
        s.finding(OK, f"OpenSanctions: no match for '{name}'.")


# =====================================================================================
#  9. Structure & fragmentation
# =====================================================================================

def check_structure(rep, ctx):
    s = rep.section("Structure & fragmentation",
                    "Is the range cleanly routable, and how does it sit inside the holder's block?")
    net = ctx.net
    s.sub("Size and routability")
    s.kv("Prefix", str(net))
    s.kv("Addresses", f"{net.num_addresses:,}")
    s.kv("Number of /24s", len(ctx.all24) if net.prefixlen <= 24 else "less than one /24")
    if len(ctx.all24) > len(ctx.nets24):
        s.finding(INFO, f"Large range: per-/24 checks were run on a sample of {len(ctx.nets24)} of "
                        f"{len(ctx.all24)} /24s.")
    if net.prefixlen > 24:
        s.finding(HIGH, "Prefix is longer than /24 - it cannot be announced on its own on the Internet "
                        "(most networks filter anything smaller than a /24).")
    else:
        s.finding(OK, f"/{net.prefixlen} is globally routable (/24 or larger).")
    s.sub("Position inside the holder's block")
    for h in ctx.holders:
        pos = ctx.start - h.start
        s.kv("Position in holder block", f"{str(net)} starts at offset {pos:,} of {h.key} ({h.size:,} addresses)")
        rest = h.size - overlap_size(h.start, h.end, ctx.start, ctx.end)
        if rest:
            s.kv("Holder keeps", f"{rest:,} addresses in the same block")
    s.text("")
    s.text("Aggregation with your other ranges is shown in the PORTFOLIO SUMMARY when you check "
           "several supernets together.", 4)


# =====================================================================================
#  Driver
# =====================================================================================

CHECKS = [
    ("Registry ownership", check_registry),
    ("Transfer history", check_transfers),
    ("BGP / routing history", check_bgp),
    ("RPKI & IRR", check_rpki_irr),
    ("IP reputation", check_reputation),
    ("Geolocation", check_geo),
    ("Past usage", check_past_usage),
    ("Legal & compliance", check_legal),
    ("Structure", check_structure),
]


def run_supernet(net, args):
    meta = {}
    keys = ["ABUSEIPDB_API_KEY", "IPQS_API_KEY", "OTX_API_KEY", "GREYNOISE_API_KEY", "IPINFO_TOKEN",
            "SHODAN_API_KEY", "SPAMHAUS_DQS_KEY", "OPENSANCTIONS_API_KEY"]
    meta["Optional APIs"] = ", ".join(k.split("_")[0].lower() for k in keys if os.environ.get(k)) or \
        "none configured (free public sources only)"
    rep = Report(net, meta)
    ctx = Ctx(net, args)
    for i, (name, fn) in enumerate(CHECKS, 1):
        log(f"[{net}] {i}/{len(CHECKS)} {name} ...")
        try:
            fn(rep, ctx)
        except Exception as e:   # noqa: BLE001 - a crash in one section must not lose the report
            sec = rep.sections[-1] if rep.sections and rep.sections[-1].title.lower().startswith(name.split()[0].lower()) \
                else rep.section(name, "")
            sec.finding(UNKNOWN, f"Section aborted by an unexpected error: {type(e).__name__}: {e}")
    return rep


def portfolio_summary(reports):
    bar = "#" * WIDTH
    out = ["", bar, "#" + " PORTFOLIO SUMMARY".center(WIDTH - 2) + "#", bar, ""]
    rows = [["Supernet", "Addresses", "Verdict", "Crit", "High", "Med", "Low", "Unknown"]]
    for r in reports:
        c = r.counts()
        rows.append([str(r.net), f"{r.net.num_addresses:,}", r.verdict()[0], c[CRITICAL], c[HIGH],
                     c[MEDIUM], c[LOW], c[UNKNOWN]])
    widths = [max(len(str(x[i])) for x in rows) for i in range(len(rows[0]))]
    for j, row in enumerate(rows):
        out.append("  " + "  ".join(str(c).ljust(widths[i]) for i, c in enumerate(row)))
        if j == 0:
            out.append("  " + "  ".join("-" * w for w in widths))
    nets = [r.net for r in reports]
    total = sum(n.num_addresses for n in nets)
    collapsed = list(ipaddress.collapse_addresses(nets))
    out += ["", f"  Total addresses        : {total:,}"]
    out.append(f"  Aggregates to          : {', '.join(map(str, collapsed))}")
    if len(collapsed) < len(nets):
        out.append("  -> Some ranges are adjacent/overlapping and can be announced as fewer prefixes.")
    else:
        out.append("  -> Ranges are not contiguous; each must be announced separately.")
    overlaps = [(a, b) for i, a in enumerate(nets) for b in nets[i + 1:] if a.overlaps(b)]
    for a, b in overlaps:
        out.append(f"  !! {a} and {b} OVERLAP - you are being offered the same addresses twice.")
    out.append("")
    return "\n".join(out)


def parse_supernets(text):
    nets, errors = [], []
    for tok in re.split(r"[\s,;]+", text.strip()):
        if not tok:
            continue
        try:
            n = ipaddress.ip_network(tok, strict=False)
        except ValueError:
            errors.append(f"'{tok}' is not a valid IPv4 prefix (expected e.g. 193.0.0.0/21)")
            continue
        if n.version != 4:
            errors.append(f"'{tok}' is IPv6 - this tool checks IPv4 ranges only")
            continue
        if str(n) != tok and "/" in tok:
            print(f"  note: '{tok}' has host bits set - using the network {n}", file=sys.stderr)
        if not n.is_global:
            errors.append(f"'{tok}' is private/reserved space - nothing to buy there")
            continue
        nets.append(n)
    return nets, errors


def main():
    ap = argparse.ArgumentParser(description="Pre-purchase due-diligence report for IPv4 ranges (RIPE NCC).")
    ap.add_argument("supernets", nargs="*", help="one or more IPv4 prefixes, e.g. 193.0.0.0/21")
    ap.add_argument("--full-dnsbl", action="store_true",
                    help="check EVERY IP against the DNS blocklists (default: 5 samples per /24)")
    ap.add_argument("--output-dir", default=".", help="where to save the text report(s)")
    ap.add_argument("--no-save", action="store_true", help="print only, do not save report files")
    args = ap.parse_args()

    text = " ".join(args.supernets)
    while True:
        if not text:
            try:
                text = input("Enter the supernet(s) to check (e.g. 193.0.0.0/21, separate several with commas): ")
            except EOFError:
                return 1
        nets, errors = parse_supernets(text)
        for e in errors:
            print(f"  error: {e}", file=sys.stderr)
        if nets and not errors:
            break
        if args.supernets:
            return 2
        text = ""

    reports = []
    for net in nets:
        print(f"\nChecking {net} - this takes 1-3 minutes ...", file=sys.stderr)
        rep = run_supernet(net, args)
        reports.append(rep)
        body = rep.render()
        print(body)
        if not args.no_save:
            os.makedirs(args.output_dir, exist_ok=True)
            fname = os.path.join(args.output_dir,
                                 f"ip_report_{str(net).replace('/', '_')}_{NOW.strftime('%Y%m%d')}.txt")
            with open(fname, "w", encoding="utf-8") as f:
                f.write(body)
            print(f"\n  Report saved to {fname}", file=sys.stderr)
    if len(reports) > 1:
        summary = portfolio_summary(reports)
        print(summary)
        if not args.no_save:
            fname = os.path.join(args.output_dir, f"ip_report_portfolio_{NOW.strftime('%Y%m%d')}.txt")
            with open(fname, "w", encoding="utf-8") as f:
                f.write(summary)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        sys.exit(130)
