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
ABUSECH_API_KEY = os.environ.get("ABUSECH_API_KEY", "")

ABUSEIPDB_MIN_CONFIDENCE = 90
VT_FEED_LIMIT            = 200
OTX_PULSE_LIMIT          = 30
SHODAN_QUERY             = "category:malware"
THREATFOX_DAYS            = 1

# Cross-source confidence scoring
# An IOC must appear in this many distinct sources to be written to combined_malicious_*.txt
MIN_CONFIDENCE_SOURCES = 2

OUTPUT_DIR = "reports"

iocs = {
    "virustotal": defaultdict(set),
    "abuseipdb":  defaultdict(set),
    "otx":        {"ips": set(), "hashes": set(), "urls": [], "domains": []},
    "threatfox":   {"ips": set(), "urls": [], "domains": []},
    "shodan":     defaultdict(set),
    "urlhaus":    {"urls": []},
    "malwarebazaar": defaultdict(set),
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


def save_urls_csv(source, rows):
    if not rows:
        log("OUTPUT", f"{source}_urls.csv — skipped (0 IOCs)")
        return
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    filename = f"{source}_urls.csv"
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


def normalize_threatfox_ts(ts):
    if not ts:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    ts = str(ts).strip()
    if ts.endswith(" UTC"):
        ts = ts[:-4]
    return ts


def normalize_threatfox_tags(tags):
    if not tags:
        return ""
    if isinstance(tags, list):
        return " ".join(f"#{t}" for t in tags if str(t).strip())
    return str(tags).strip()


def save_all():
    print("-" * 60)
    for source, types in iocs.items():
        for ioc_type, data in types.items():
            if ioc_type == "domains" and isinstance(data, list):
                save_domains_csv(source, data)
            elif ioc_type == "urls" and isinstance(data, list):
                save_urls_csv(source, data)
            else:
                save(source, ioc_type, data)
    print("-" * 60)

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
                    elif ioc_type == "urls":
                        iocs["otx"]["urls"].append({
                            "date":      ts,
                            "reporter":  pulse_name,
                            "type":      "url",
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

def fetch_urlhaus():
    if not ABUSECH_API_KEY:
        log("URLhaus", "Skipped — ABUSECH_API_KEY not set")
        return

    try:
        resp = requests.get(
            "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/0/",
            headers={"Auth-Key": ABUSECH_API_KEY},
            params={"auth-key": ABUSECH_API_KEY},
            timeout=60
        )

        if resp.status_code == 301 or "auth-key" in resp.url:
            resp = requests.get(
                f"https://urlhaus-api.abuse.ch/files/exports/recent.csv?auth-key={ABUSECH_API_KEY}",
                timeout=60
            )

        resp.raise_for_status()

        lines = resp.text.splitlines()
        before = len(iocs["urlhaus"]["urls"])

        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            parts = line.split(",", 8)
            if len(parts) < 8:
                continue

            url_val    = parts[2].strip().strip('"')
            url_status = parts[3].strip().strip('"')
            threat     = parts[5].strip().strip('"')
            tags       = parts[6].strip().strip('"')
            reporter   = parts[8].strip().strip('"') if len(parts) > 8 else "urlhaus"
            date_added = parts[1].strip().strip('"')
            reference  = parts[7].strip().strip('"')

            if not url_val or not url_val.startswith("http"):
                continue

            iocs["urlhaus"]["urls"].append({
                "date":      date_added,
                "reporter":  reporter,
                "type":      "url",
                "ioc":       url_val,
                "tags":      tags,
                "reference": reference,
            })

        log("URLhaus", f"urls → {len(iocs['urlhaus']['urls']) - before} malicious URLs fetched")

    except requests.HTTPError as e:
        log("URLhaus", f"HTTP {e.response.status_code}: {e.response.text[:120]}")
    except Exception as e:
        log("URLhaus", f"Error: {e}")


def fetch_threatfox():
    if not ABUSECH_API_KEY:
        log("ThreatFox", "Skipped — ABUSECH_API_KEY not set")
        return

    try:
        resp = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            headers={"Auth-Key": ABUSECH_API_KEY, "Accept": "application/json"},
            json={"query": "get_iocs", "days": THREATFOX_DAYS},
            timeout=60,
        )
        resp.raise_for_status()
        payload = resp.json()
        if payload.get("query_status") != "ok":
            log("ThreatFox", f"API returned query_status={payload.get('query_status')}")
            return

        for entry in payload.get("data", []) or []:
            ioc_val = str(entry.get("ioc", "")).strip()
            ioc_type = str(entry.get("ioc_type", "")).strip().lower()
            if not ioc_val or not ioc_type:
                continue

            ts = normalize_threatfox_ts(entry.get("first_seen"))
            reporter = str(entry.get("malware_printable") or entry.get("reporter") or "threatfox").strip()
            tags = normalize_threatfox_tags(entry.get("tags"))
            ref = entry.get("reference")
            if not ref:
                ioc_id = str(entry.get("id", "")).strip()
                ref = f"https://threatfox.abuse.ch/ioc/{ioc_id}/" if ioc_id else ""

            if ioc_type in {"domain", "hostname"}:
                iocs["threatfox"]["domains"].append({
                    "date": ts,
                    "reporter": reporter,
                    "type": "domain",
                    "ioc": ioc_val,
                    "tags": tags,
                    "reference": ref,
                })
            elif ioc_type == "url":
                iocs["threatfox"]["urls"].append({
                    "date": ts,
                    "reporter": reporter,
                    "type": "url",
                    "ioc": ioc_val,
                    "tags": tags,
                    "reference": ref,
                })
            elif ioc_type == "ip:port":
                ip_only = ioc_val.split(":", 1)[0].strip()
                if ip_only:
                    iocs["threatfox"]["ips"].add(ip_only)
            elif ioc_type == "ip":
                iocs["threatfox"]["ips"].add(ioc_val)

        totals = {t: len(v) for t, v in iocs["threatfox"].items()}
        log("ThreatFox", f"IPs={totals.get('ips',0)}  Domains={totals.get('domains',0)}  URLs={totals.get('urls',0)}")

    except requests.HTTPError as e:
        log("ThreatFox", f"HTTP {e.response.status_code}: {e.response.text[:120]}")
    except Exception as e:
        log("ThreatFox", f"Error: {e}")


def fetch_malwarebazaar():
    if not ABUSECH_API_KEY:
        log("MalwareBazaar", "Skipped — ABUSECH_API_KEY not set")
        return

    try:
        resp = requests.post(
            "https://mb-api.abuse.ch/api/v1/",
            headers={"Auth-Key": ABUSECH_API_KEY, "Accept": "application/json"},
            data={"query": "get_recent", "selector": "100"},
            timeout=60,
        )
        resp.raise_for_status()
        payload = resp.json()
        if payload.get("query_status") != "ok":
            log("MalwareBazaar", f"API returned query_status={payload.get('query_status')}")
            return

        for entry in payload.get("data", []) or []:
            sha256_hash = str(entry.get("sha256_hash", "")).strip()
            if sha256_hash:
                iocs["malwarebazaar"]["hashes"].add(sha256_hash)

        log("MalwareBazaar", f"hashes → {len(iocs['malwarebazaar']['hashes'])} IOCs")

    except requests.HTTPError as e:
        log("MalwareBazaar", f"HTTP {e.response.status_code}: {e.response.text[:120]}")
    except Exception as e:
        log("MalwareBazaar", f"Error: {e}")

# ---------------------------------------------------------------------------
# Cross-source confidence scoring
# ---------------------------------------------------------------------------

def compute_cross_source_scores():
    """
    After all feeds have run, build a per-IOC-type map of:
        { ioc_value: set_of_sources_that_reported_it }

    Returns a dict with keys: 'ips', 'hashes', 'domains', 'urls'.
    The confidence score of an IOC equals the number of sources in its set.
    """
    scores = {
        "ips":     defaultdict(set),
        "hashes":  defaultdict(set),
        "domains": defaultdict(set),
        "urls":    defaultdict(set),
    }

    for source, types in iocs.items():
        for ioc_type, data in types.items():
            if ioc_type not in scores:
                continue
            if isinstance(data, set):
                # Plain set of IOC strings
                for val in data:
                    val = val.strip()
                    if val:
                        scores[ioc_type][val].add(source)
            elif isinstance(data, list):
                # Enriched list of dicts (CSV rows) — extract the 'ioc' key
                for row in data:
                    val = row.get("ioc", "").strip()
                    if val:
                        scores[ioc_type][val].add(source)

    return scores


def save_scored_csvs(scores):
    """
    Write reports/scored_{type}.csv for each IOC type.
    Columns: ioc, score, sources
    Sorted by score descending, then alphabetically by IOC.
    """
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    for ioc_type, ioc_map in scores.items():
        if not ioc_map:
            log("SCORE", f"scored_{ioc_type}.csv — skipped (0 IOCs)")
            continue
        filename = f"scored_{ioc_type}.csv"
        path     = os.path.join(OUTPUT_DIR, filename)
        rows = sorted(
            [
                {
                    "ioc":     k,
                    "score":   len(v),
                    "sources": ",".join(sorted(v)),
                }
                for k, v in ioc_map.items()
            ],
            key=lambda r: (-r["score"], r["ioc"]),
        )
        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["ioc", "score", "sources"])
            writer.writeheader()
            writer.writerows(rows)
        multi = sum(1 for r in rows if r["score"] >= MIN_CONFIDENCE_SOURCES)
        log("SCORE", f"{filename} → {len(rows)} unique IOCs  "
                     f"({multi} meet {MIN_CONFIDENCE_SOURCES}+ source threshold)")


def save_combined_files(scores):
    """
    Write reports/combined_malicious_{type}.txt containing only IOCs whose
    confidence score (number of distinct sources) >= MIN_CONFIDENCE_SOURCES.
    """
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    print("-" * 60)
    for ioc_type, ioc_map in scores.items():
        high_conf = sorted(
            ioc for ioc, sources in ioc_map.items()
            if len(sources) >= MIN_CONFIDENCE_SOURCES
        )
        filename = f"combined_malicious_{ioc_type}.txt"
        path     = os.path.join(OUTPUT_DIR, filename)
        if not high_conf:
            log("COMBINED", f"{filename} — skipped "
                            f"(0 IOCs matched {MIN_CONFIDENCE_SOURCES}+ sources)")
            continue
        with open(path, "w") as f:
            f.write("\n".join(high_conf) + "\n")
        log("COMBINED", f"{filename} → {len(high_conf)} high-confidence IOCs "
                        f"(seen in {MIN_CONFIDENCE_SOURCES}+ sources)")
    print("-" * 60)


# ---------------------------------------------------------------------------

if __name__ == "__main__":
    run_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    print("=" * 60)
    print(f"  IOC Collection Run — {run_ts}")
    print("=" * 60)

    fetch_virustotal()
    fetch_abuseipdb()
    fetch_otx()
    fetch_shodan()
    fetch_urlhaus()
    fetch_threatfox()
    fetch_malwarebazaar()

    # Print grand totals per source
    print("-" * 60)
    for source, types in iocs.items():
        total     = sum(len(v) for v in types.values())
        breakdown = "  ".join(f"{t}={len(v)}" for t, v in types.items())
        print(f"  {source.upper():<12} total={total}  [{breakdown}]")

    # Write per-source files (unchanged behaviour)
    save_all()

    # Compute cross-source confidence scores and write combined outputs
    scores = compute_cross_source_scores()
    save_scored_csvs(scores)
    save_combined_files(scores)

    # Exit non-zero if absolutely nothing was collected
    grand_total = sum(len(v) for types in iocs.values() for v in types.values())
    if grand_total == 0:
        log("MAIN", "WARNING: No IOCs collected. Check API keys and feed access.")
        sys.exit(1)

    print("  Done.")