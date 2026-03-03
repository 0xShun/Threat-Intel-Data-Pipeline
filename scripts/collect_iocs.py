import os
import sys
import csv
import requests
from datetime import datetime, timezone
from collections import defaultdict

VT_API_KEY      = os.environ.get("VT_API_KEY", "")
ABUSEIPDB_KEY   = os.environ.get("ABUSEIPDB_KEY", "")
OTX_API_KEY     = os.environ.get("OTX_API_KEY", "")
SHODAN_API_KEY  = os.environ.get("SHODAN_API_KEY", "")

ABUSEIPDB_MIN_CONFIDENCE = 90   # Only IPs with confidence >= this value
VT_FEED_LIMIT            = 200  # Max items per VT feed call
OTX_PULSE_LIMIT          = 30   # Max number of recent OTX pulses to scan
SHODAN_QUERY             = "category:malware"

OUTPUT_DIR = "reports"

iocs = {
    "virustotal": defaultdict(set),
    "abuseipdb":  defaultdict(set),
    "otx":        {"ips": set(), "hashes": set(), "urls": set(), "domains": []},
    "shodan":     defaultdict(set),
}

def log(source, msg):
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    print(f"[{ts}] [{source}] {msg}")


def save(source, ioc_type, data):
    if not data:
        log("OUTPUT", f"{source}_{ioc_type}.txt — skipped (0 IOCs)")
        return
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    filename = f"{source}_{ioc_type}.txt"
    path     = os.path.join(OUTPUT_DIR, filename)
    sorted_data = sorted(data)
    with open(path, "w") as f:
        f.write("\n".join(sorted_data) + "\n")
    log("OUTPUT", f"{filename} → {len(sorted_data)} IOCs")


def save_domains_csv(source, rows):
    if not rows:
        log("OUTPUT", f"{source}_domains.csv — skipped (0 IOCs)")
        return
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    filename = f"{source}_domains.csv"
    path     = os.path.join(OUTPUT_DIR, filename)
    seen     = set()
    unique_rows = []
    for row in rows:
        if row["ioc"] not in seen:
            seen.add(row["ioc"])
            unique_rows.append(row)
    unique_rows.sort(key=lambda r: r["ioc"])
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["date", "reporter", "type", "ioc", "tags", "reference"])
        writer.writerows(unique_rows)
    log("OUTPUT", f"{filename} → {len(unique_rows)} IOCs")


def save_all():
    for source, types in iocs.items():
        for ioc_type, data in types.items():
            if source == "otx" and ioc_type == "domains":
                save_domains_csv(source, data)
            else:
                save(source, ioc_type, data)

def fetch_virustotal():
    if not VT_API_KEY:
        log("VT", "Skipped — VT_API_KEY not set")
        return

    headers = {"x-apikey": VT_API_KEY}
    feeds = [
        ("https://www.virustotal.com/api/v3/feeds/ip-addresses", "ips"),
        ("https://www.virustotal.com/api/v3/feeds/files",        "hashes"),
        ("https://www.virustotal.com/api/v3/feeds/domains",      "domains"),
        ("https://www.virustotal.com/api/v3/feeds/urls",         "urls"),
    ]

    for feed_url, ioc_type in feeds:
        try:
            resp = requests.get(
                feed_url,
                headers=headers,
                params={"limit": VT_FEED_LIMIT},
                timeout=30
            )
            resp.raise_for_status()
            items = resp.json().get("data", [])
            for item in items:
                val = item.get("id", "").strip()
                if val:
                    iocs["virustotal"][ioc_type].add(val)
            log("VT", f"{ioc_type} feed → {len(iocs['virustotal'][ioc_type])} IOCs")
        except requests.HTTPError as e:
            log("VT", f"{ioc_type} HTTP {e.response.status_code}: {e.response.text[:120]}")
        except Exception as e:
            log("VT", f"{ioc_type} error: {e}")

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
        for entry in resp.json().get("data", []):
            ip = entry.get("ipAddress", "").strip()
            if ip:
                iocs["abuseipdb"]["ips"].add(ip)
        log("AbuseIPDB", f"ips → {len(iocs['abuseipdb']['ips'])} IOCs "
                         f"(confidence >= {ABUSEIPDB_MIN_CONFIDENCE})")
    except requests.HTTPError as e:
        log("AbuseIPDB", f"HTTP {e.response.status_code}: {e.response.text[:120]}")
    except Exception as e:
        log("AbuseIPDB", f"Error: {e}")

def fetch_otx():
    if not OTX_API_KEY:
        log("OTX", "Skipped — OTX_API_KEY not set")
        return

    OTX_TYPE_MAP = {
        "IPv4":            "ips",
        "IPv6":            "ips",
        "FileHash-SHA256": "hashes",
        "FileHash-MD5":    "hashes",
        "FileHash-SHA1":   "hashes",
        "domain":          "domains",
        "hostname":        "domains",
        "URL":             "urls",
    }

    try:
        page    = 1
        fetched = 0
        while fetched < OTX_PULSE_LIMIT:
            resp = requests.get(
                "https://otx.alienvault.com/api/v1/pulses/subscribed",
                headers={"X-OTX-API-KEY": OTX_API_KEY},
                params={"limit": 10, "page": page},
                timeout=30
            )
            resp.raise_for_status()
            data    = resp.json()
            results = data.get("results", [])
            if not results:
                break

            for pulse in results:
                pulse_name = pulse.get("name", "OTX")
                pulse_tags = " ".join(f"#{t}" for t in pulse.get("tags", []))
                pulse_url  = f"https://otx.alienvault.com/pulse/{pulse.get('id','')}"
                ts         = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

                for indicator in pulse.get("indicators", []):
                    ioc_type = OTX_TYPE_MAP.get(indicator.get("type", ""))
                    ioc_val  = indicator.get("indicator", "").strip()
                    if not ioc_type or not ioc_val:
                        continue
                    if ioc_type == "domains":
                        iocs["otx"]["domains"].append({
                            "date":      ts,
                            "reporter":  pulse_name,
                            "type":      "domain",
                            "ioc":       ioc_val,
                            "tags":      pulse_tags,
                            "reference": pulse_url,
                        })
                    else:
                        iocs["otx"][ioc_type].add(ioc_val)

            fetched += len(results)
            page    += 1
            if not data.get("next"):
                break

        totals = {t: len(v) for t, v in iocs["otx"].items()}
        log("OTX", f"IPs={totals.get('ips',0)}  Hashes={totals.get('hashes',0)}  "
                   f"Domains={totals.get('domains',0)}  URLs={totals.get('urls',0)}")

    except requests.HTTPError as e:
        log("OTX", f"HTTP {e.response.status_code}: {e.response.text[:120]}")
    except Exception as e:
        log("OTX", f"Error: {e}")

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
        for host in resp.json().get("matches", []):
            ip = host.get("ip_str", "").strip()
            if ip:
                iocs["shodan"]["ips"].add(ip)
        log("Shodan", f"ips → {len(iocs['shodan']['ips'])} IOCs (query: '{SHODAN_QUERY}')")
    except requests.HTTPError as e:
        log("Shodan", f"HTTP {e.response.status_code}: {e.response.text[:120]}")
    except Exception as e:
        log("Shodan", f"Error: {e}")

if __name__ == "__main__":
    run_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    print(f"  IOC Collection Run — {run_ts}")

    fetch_virustotal()
    fetch_abuseipdb()
    fetch_otx()
    fetch_shodan()

    # Print grand totals per source
    print("-" * 60)
    for source, types in iocs.items():
        total     = sum(len(v) for v in types.values())
        breakdown = "  ".join(f"{t}={len(v)}" for t, v in types.items())
        print(f"  {source.upper():<12} total={total}  [{breakdown}]")

    # Write all files
    save_all()

    # Exit non-zero if absolutely nothing was collected
    grand_total = sum(len(v) for types in iocs.values() for v in types.values())
    if grand_total == 0:
        log("MAIN", "WARNING: No IOCs collected. Check API keys and feed access.")
        sys.exit(1)

    print("  Done.")