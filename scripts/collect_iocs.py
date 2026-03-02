"""
IOC Collector
=============
Pulls the latest malicious IOCs from:
  - VirusTotal  (IPs, Hashes, Domains, URLs)
  - AbuseIPDB   (IPs)
  - AlienVault OTX (IPs, Hashes, Domains, URLs)
  - Shodan      (IPs)

Outputs (one IOC per line, deduplicated, overwritten each run):
  reports/ips.txt
  reports/hashes.txt
  reports/domains.txt
  reports/urls.txt
"""

import os
import sys
import requests
from datetime import datetime, timezone

# ── API Keys (injected by GitHub Actions secrets) ────────────────────────────
VT_API_KEY       = os.environ.get("VT_API_KEY", "")
ABUSEIPDB_KEY    = os.environ.get("ABUSEIPDB_KEY", "")
OTX_API_KEY      = os.environ.get("OTX_API_KEY", "")
SHODAN_API_KEY   = os.environ.get("SHODAN_API_KEY", "")

# ── Config ───────────────────────────────────────────────────────────────────
ABUSEIPDB_MIN_CONFIDENCE = 90    # Only IPs with confidence >= this value
VT_FEED_LIMIT            = 200   # Max items per VT feed call
OTX_PULSE_LIMIT          = 30    # Number of recent OTX pulses to scan
SHODAN_QUERY             = "category:malware"

OUTPUT_DIR = "reports"

# Buckets
ips     = set()
hashes  = set()
domains = set()
urls    = set()


# ════════════════════════════════════════════════════════════════════════════
# HELPERS
# ════════════════════════════════════════════════════════════════════════════

def log(source: str, msg: str):
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    print(f"[{ts}] [{source}] {msg}")


def save(filename: str, data: set):
    path = os.path.join(OUTPUT_DIR, filename)
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    sorted_data = sorted(data)
    with open(path, "w") as f:
        f.write("\n".join(sorted_data))
        if sorted_data:
            f.write("\n")
    log("OUTPUT", f"{filename} → {len(sorted_data)} IOCs written to {path}")


# ════════════════════════════════════════════════════════════════════════════
# VIRUSTOTAL
# Requires VT Enterprise/Premium for /feeds endpoints
# Docs: https://developers.virustotal.com/reference/feeds
# ════════════════════════════════════════════════════════════════════════════

def fetch_virustotal():
    if not VT_API_KEY:
        log("VT", "Skipped — VT_API_KEY not set")
        return

    headers = {"x-apikey": VT_API_KEY}
    feeds = [
        ("https://www.virustotal.com/api/v3/feeds/ip-addresses", "ip",     ips),
        ("https://www.virustotal.com/api/v3/feeds/files",        "hash",   hashes),
        ("https://www.virustotal.com/api/v3/feeds/domains",      "domain", domains),
        ("https://www.virustotal.com/api/v3/feeds/urls",         "url",    urls),
    ]

    for feed_url, kind, bucket in feeds:
        try:
            resp = requests.get(
                feed_url,
                headers=headers,
                params={"limit": VT_FEED_LIMIT},
                timeout=30
            )
            resp.raise_for_status()
            items = resp.json().get("data", [])
            before = len(bucket)
            for item in items:
                val = item.get("id", "").strip()
                if val:
                    bucket.add(val)
            log("VT", f"{kind} feed → +{len(bucket) - before} IOCs")
        except requests.HTTPError as e:
            # 403 = no premium access, 429 = rate limited
            log("VT", f"{kind} feed HTTP error: {e.response.status_code} {e.response.text[:120]}")
        except Exception as e:
            log("VT", f"{kind} feed error: {e}")


# ════════════════════════════════════════════════════════════════════════════
# ABUSEIPDB
# Docs: https://docs.abuseipdb.com/#blacklist-endpoint
# Free tier: up to 10,000 IPs at confidence >= 100
# Basic tier: configurable confidence threshold
# ════════════════════════════════════════════════════════════════════════════

def fetch_abuseipdb():
    if not ABUSEIPDB_KEY:
        log("AbuseIPDB", "Skipped — ABUSEIPDB_KEY not set")
        return

    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/blacklist",
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            params={
                "confidenceMinimum": ABUSEIPDB_MIN_CONFIDENCE,
                "limit": 10000,
            },
            timeout=30
        )
        resp.raise_for_status()
        entries = resp.json().get("data", [])
        before = len(ips)
        for entry in entries:
            ip = entry.get("ipAddress", "").strip()
            if ip:
                ips.add(ip)
        log("AbuseIPDB", f"Blacklist → +{len(ips) - before} IPs (confidence >= {ABUSEIPDB_MIN_CONFIDENCE})")
    except requests.HTTPError as e:
        log("AbuseIPDB", f"HTTP error: {e.response.status_code} {e.response.text[:120]}")
    except Exception as e:
        log("AbuseIPDB", f"Error: {e}")


# ════════════════════════════════════════════════════════════════════════════
# ALIENVAULT OTX
# Docs: https://otx.alienvault.com/api
# Uses the official OTXv2 Python SDK
# ════════════════════════════════════════════════════════════════════════════

def fetch_otx():
    if not OTX_API_KEY:
        log("OTX", "Skipped — OTX_API_KEY not set")
        return

    try:
        from OTXv2 import OTXv2
        otx = OTXv2(OTX_API_KEY)

        # Pull the latest subscribed pulses
        pulses = otx.getall(max_items=OTX_PULSE_LIMIT)

        before_ip  = len(ips)
        before_h   = len(hashes)
        before_d   = len(domains)
        before_u   = len(urls)

        OTX_TYPE_MAP = {
            # IPs
            "IPv4":              ips,
            "IPv6":              ips,
            # Hashes
            "FileHash-SHA256":   hashes,
            "FileHash-MD5":      hashes,
            "FileHash-SHA1":     hashes,
            # Domains
            "domain":            domains,
            "hostname":          domains,
            # URLs
            "URL":               urls,
        }

        for pulse in pulses:
            for indicator in pulse.get("indicators", []):
                ioc_type = indicator.get("type", "")
                ioc_val  = indicator.get("indicator", "").strip()
                bucket   = OTX_TYPE_MAP.get(ioc_type)
                if bucket is not None and ioc_val:
                    bucket.add(ioc_val)

        log("OTX", f"IPs +{len(ips)-before_ip}  Hashes +{len(hashes)-before_h}  "
                   f"Domains +{len(domains)-before_d}  URLs +{len(urls)-before_u}")

    except ImportError:
        log("OTX", "OTXv2 SDK not installed — run: pip install OTXv2")
    except Exception as e:
        log("OTX", f"Error: {e}")


# ════════════════════════════════════════════════════════════════════════════
# SHODAN
# Docs: https://developer.shodan.io/api
# Note: Shodan free tier has limited search credits
# ════════════════════════════════════════════════════════════════════════════

def fetch_shodan():
    if not SHODAN_API_KEY:
        log("Shodan", "Skipped — SHODAN_API_KEY not set")
        return

    try:
        resp = requests.get(
            "https://api.shodan.io/shodan/host/search",
            params={
                "key":   SHODAN_API_KEY,
                "query": SHODAN_QUERY,
                "page":  1,
            },
            timeout=30
        )
        resp.raise_for_status()
        matches = resp.json().get("matches", [])
        before = len(ips)
        for host in matches:
            ip = host.get("ip_str", "").strip()
            if ip:
                ips.add(ip)
        log("Shodan", f"Query '{SHODAN_QUERY}' → +{len(ips) - before} IPs")
    except requests.HTTPError as e:
        log("Shodan", f"HTTP error: {e.response.status_code} {e.response.text[:120]}")
    except Exception as e:
        log("Shodan", f"Error: {e}")


# ════════════════════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    run_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    print("=" * 60)
    print(f"  IOC Collection Run — {run_ts}")
    print("=" * 60)

    fetch_virustotal()
    fetch_abuseipdb()
    fetch_otx()
    fetch_shodan()

    print("-" * 60)
    print(f"  Totals → IPs: {len(ips)}  Hashes: {len(hashes)}  "
          f"Domains: {len(domains)}  URLs: {len(urls)}")
    print("-" * 60)

    save("ips.txt",     ips)
    save("hashes.txt",  hashes)
    save("domains.txt", domains)
    save("urls.txt",    urls)

    # Exit non-zero if ALL sources returned nothing (likely all keys missing)
    if not any([ips, hashes, domains, urls]):
        log("MAIN", "WARNING: No IOCs collected. Check API keys and feed access.")
        sys.exit(1)

    print("  Done.")
