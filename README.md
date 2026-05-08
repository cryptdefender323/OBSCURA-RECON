# OBSCURA RECON

Advanced web reconnaissance tool with multi-round discovery, CVE correlation, and anomaly detection.

Built this because I got tired of manually filtering through hundreds of false positives from other scanners. Every hit here is double-checked before it shows up in your report.

---

## What It Does

- **Multi-round scanning** — finds stuff other tools miss by iterating on discovered paths
- **Technology fingerprinting** — detects CMS, frameworks, servers, WAF/CDN (30+ signatures)
- **CVE correlation** — matches detected versions to known vulnerabilities with CVSS scores
- **Anomaly detection** — flags unusual response patterns (singleton/rare responses)
- **WAF bypass** — 4 levels of evasion techniques when you need them
- **Professional reports** — PDF and JSON output with executive summaries

---

## Quick Start

### Install

```bash

git clone https://github.com/cryptdefender323/OBSCURA-RECON.git
cd OBSCURA-RECON

go build -o obscura

brew install gobuster  # macOS
```

### Basic Usage

```bash

./obscura -u https://example.com -w wordlists/common.txt -r 3 --report-pdf report.pdf


./obscura -u https://example.com -w wordlists/big.txt -r 3 -x php,js,txt,bak --report-pdf report.pdf


./obscura -u https://target.com -w wordlists/big.txt -r 5 -x php,asp,aspx,jsp,js,txt,bak,zip,sql -d 2 --report-pdf report.pdf --report-json report.json
```

---

## Flags

```
Required:
  -u, --url string          Target URL (e.g. https://example.com)
  -w, --wordlist string     Wordlist file path

Optional:
  -r, --rounds int          Max discovery rounds (default: 3)
  -x, --extensions string   File extensions (e.g. php,js,txt)
  -d, --depth int           Recursion depth (default: 1)
  
  --waf-level int           WAF bypass level 0-3 (default: 0)
  --status-codes string     Include only these codes (e.g. 200,301,302)
  --exclude-codes string    Exclude these codes (e.g. 404,403)
  --exclude-length string   Exclude response lengths (e.g. 1580,0)
  
  --report-pdf string       PDF output path (default: "report.pdf")
  --report-json string      JSON output path (optional)
  
  --wildcard                Force continue on wildcard detection
  --no-auto-filter          Disable smart wildcard filtering
  -f, --add-slash           Append / to requests
```

**Note:** Don't use `--status-codes` and `--exclude-codes` together (gobuster limitation). Pick one.

---

## Examples

### E-Commerce Site
```bash
./obscura \
  -u https://shop.example.com \
  -w wordlists/big.txt \
  -r 3 \
  -x php,js,txt,bak,zip,sql \
  --status-codes 200,301,302,403 \
  --report-pdf shop-report.pdf
```

Finds admin panels, backup files, config files. Auto-saves sensitive stuff to `loot/` folder.

### API Discovery
```bash
./obscura \
  -u https://api.example.com \
  -w wordlists/common.txt \
  -r 5 \
  -x json,xml \
  -d 2 \
  --status-codes 200,401,403 \
  --report-pdf api-report.pdf
```

Discovers API endpoints, versions (v1, v2), auth-protected routes. Recursive depth 2 finds nested paths.

### Government Site (with WAF)
```bash
./obscura \
  -u https://gov-site.go.id \
  -w wordlists/directory-list-2.3-small.txt \
  -r 5 \
  -x php,asp,txt \
  --waf-level 2 \
  --status-codes 200,301,302 \
  --report-pdf gov-report.pdf
```

WAF bypass level 2 adds randomized headers and browser signatures. Level 3 attempts origin IP detection.

### Quick Recon (5 minutes)
```bash
./obscura \
  -u https://target.com \
  -w wordlists/common.txt \
  -r 2 \
  --status-codes 200,301 \
  --report-pdf quick.pdf
```

Fast initial scan. Good for getting a feel for the target before going deeper.

---

## How It Works

### Multi-Round Discovery

1. **Round 0** — Fingerprint the root domain
2. **Round 1** — Scan with base wordlist
3. **Round 2+** — Generate dynamic wordlist from discovered paths and responses
4. Repeat until no new paths found or max rounds reached

Each round builds on the previous one. If it finds `/api/v1/users`, next round tries `/api/v2/users`, `/api/v3/users`, etc.

### Validation

Every hit goes through double-validation:
1. First request from gobuster
2. Two independent verification requests
3. Only reported if all three agree on status + length

This filters out dynamic/flaky responses that would otherwise be noise.

### CVE Matching

Uses semantic version comparison, not substring matching:
- ✅ "WordPress 6.4.2" matches CVE for "6.4.2"
- ❌ "WordPress 1.2" does NOT match CVE for "1.20" or "11.2"

Queries cve.circl.lu API and includes CVSS scores in the report.

### Anomaly Detection

Clusters responses by (status, length, body hash). Flags anything that's:
- Singleton (only 1 response with this pattern)
- Rare (≤10% of dominant cluster size)

Only reports "Confirmed" and "Likely" confidence levels. Filters out noise.

### WAF Bypass Levels

- **Level 0** — No bypass (default)
- **Level 1** — Basic headers (X-Forwarded-For, X-Real-IP)
- **Level 2** — Advanced (randomized bypass headers, browser signatures)
- **Level 3** — Full (origin IP detection, X-Original-URL, encoding tricks)

Level 3 attempts to find the real origin server behind CDN/WAF by probing common origin subdomains and validating content similarity.

---

## Output

### PDF Report

Professional report with:
- Executive summary + risk rating
- Validated CVE findings (with CVSS scores)
- Detected technologies (CMS, frameworks, servers)
- Critical anomalies (high-confidence only)
- Full discovery log

### JSON Report

Machine-readable format for automation:
```json
{
  "TargetURL": "https://example.com",
  "TotalHits": 47,
  "Technologies": [...],
  "CVEs": [...],
  "Anomalies": [...]
}
```

### Loot Folder

Auto-saves sensitive files to `loot/`:
- `.env`, `.git/config`
- `database.sql`, `backup.zip`
- `config.php.bak`
- Any file matching sensitive patterns

---

## Troubleshooting

**"status-codes and status-codes-blacklist are both set"**  
Don't use `--status-codes` and `--exclude-codes` together. Pick one or the other.

**"the server returns a status code that matches the provided options"**  
Target has wildcard responses. Tool will auto-enable `--force` mode. Or remove that status code from `--status-codes`.

**Scan is slow**  
Use smaller wordlist or reduce rounds. `common.txt` is faster than `big.txt`.

**No CVEs found**  
Either target is up-to-date, or version detection failed. Check PDF report to see what versions were detected.

**Too many hits**  
Tighten your `--status-codes` filter. Or use `--exclude-length` to filter out common response sizes.

---

## Tech Stack

- **Go 1.26** — concurrency, performance
- **Gobuster** — directory brute-forcing engine
- **CVE.circl.lu API** — vulnerability data
- **Maroto** — PDF generation

---

## Wordlists

Included wordlists in `wordlists/`:
- `common.txt` — 4,614 paths (fast)
- `big.txt` — 20,469 paths (thorough)
- `directory-list-2.3-small.txt` — 87,664 paths (comprehensive)
- `raft-medium.txt` — 63,088 paths (balanced)


## Use Cases

- Penetration testing
- Bug bounty hunting
- Security assessments
- Compliance audits
- Red team engagements

---

Built by [@cryptdefender323](https://github.com/cryptdefender323)