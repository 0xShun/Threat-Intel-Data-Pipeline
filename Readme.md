# IOC Feed Collector — GitHub Actions CI/CD Pipeline

Automatically pulls the latest malicious IOCs from **VirusTotal**, **AbuseIPDB**, **AlienVault OTX**, and **Shodan** twice daily, commits them to this repo, and exposes them as raw URLs for **FortiSIEM** ingestion.

---

## Repository Structure

```
.
├── .github/
│   └── workflows/
│       └── ioc_collector.yml   # GitHub Actions workflow (schedule + logic)
├── scripts/
│   └── collect_iocs.py         # Python IOC collector script
├── reports/                    # Auto-updated output files (scraped by FortiSIEM)
│   ├── ips.txt
│   ├── hashes.txt
│   ├── domains.txt
│   └── urls.txt
├── requirements.txt
└── README.md
```

---

## Schedule

The workflow runs automatically at:
| Time (UTC) | Local equiv (PHT) |
|---|---|
| 06:00 UTC  | 2:00 PM PHT |
| 17:00 UTC  | 1:00 AM PHT |

You can also trigger it manually via **Actions → IOC Feed Collector → Run workflow**.

---

## Step 1: Add API Keys as GitHub Secrets

Go to your repo → **Settings → Secrets and variables → Actions → New repository secret**

| Secret Name | Where to get it |
|---|---|
| `VT_API_KEY` | https://www.virustotal.com/gui/my-apikey *(Enterprise required for feeds)* |
| `ABUSEIPDB_KEY` | https://www.abuseipdb.com/account/api |
| `OTX_API_KEY` | https://otx.alienvault.com/api |
| `SHODAN_API_KEY` | https://account.shodan.io |

> **Never hardcode API keys in the script or commit them to the repo.**

---

## Step 2: Get the Raw URLs for FortiSIEM

Once the workflow runs at least once, your IOC files will be available at:

```
https://raw.githubusercontent.com/<YOUR_USERNAME>/<YOUR_REPO>/main/reports/ips.txt
https://raw.githubusercontent.com/<YOUR_USERNAME>/<YOUR_REPO>/main/reports/hashes.txt
https://raw.githubusercontent.com/<YOUR_USERNAME>/<YOUR_REPO>/main/reports/domains.txt
https://raw.githubusercontent.com/<YOUR_USERNAME>/<YOUR_REPO>/main/reports/urls.txt
```

Replace `<YOUR_USERNAME>` and `<YOUR_REPO>` with your actual GitHub username and repository name.

> If your repo is **private**, FortiSIEM cannot scrape raw.githubusercontent.com directly. You have two options:
> - Make the repo **public**
> - Use a GitHub **Personal Access Token** in the FortiSIEM feed URL:
>   `https://raw.githubusercontent.com/<USER>/<REPO>/main/reports/ips.txt?token=<PAT>`

---

## Step 3: Configure FortiSIEM

1. Go to **Resources → Threat Intelligence → IP/URL/Hash Lists**
2. Click **New** and fill in:
   - **Type**: IP / Hash / Domain / URL (one feed per file)
   - **URL**: the raw GitHub URL above
   - **Pull Interval**: Every 12 hours (matches workflow schedule)
   - **Format**: Plain text, one entry per line
3. Repeat for each of the 4 files.

---

## Customization

| Setting | Location | Default |
|---|---|---|
| AbuseIPDB confidence threshold | `collect_iocs.py` → `ABUSEIPDB_MIN_CONFIDENCE` | `90` |
| VT feed item limit | `collect_iocs.py` → `VT_FEED_LIMIT` | `200` |
| OTX pulses to scan | `collect_iocs.py` → `OTX_PULSE_LIMIT` | `30` |
| Shodan search query | `collect_iocs.py` → `SHODAN_QUERY` | `category:malware` |

---

## API Tier Notes

| Source | Free Tier | Notes |
|---|---|---|
| VirusTotal | X | `/feeds` endpoints require **VT Enterprise**. Contact VT sales. |
| AbuseIPDB | / | Free tier: confidence >= 100, up to 10,000 IPs/day |
| AlienVault OTX | / | Fully free, requires account |
| Shodan | Limited | Free tier has limited search credits per month |
