import json
import os
import time
import urllib.request
from typing import Dict, Any, Optional

URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="

# Hàm lấy thông tin từ NVD
def fetch_cve(cve: str, retries: int = 2) -> Optional[Dict[str, Any]]:
    if not cve.startswith("CVE-"):
        return None

    url = f"{URL}{cve}"

    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(url)
            key = os.environ.get("NIST_API_KEY", "")

            if key:
                req.add_header("apiKey", key)
            req.add_header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
            
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                vulns = data.get("vulnerabilities", [])

                if not vulns:
                    return None

                info = vulns[0].get("cve", {})
                descs = info.get("descriptions", [])
                desc = "No description available."

                for item in descs:
                    if item.get("lang") == "en":
                        desc = item.get("value")
                        break

                metrics = info.get("metrics", {})
                cvss = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", []))

                score = 0.0
                severity = "UNKNOWN"

                if cvss:
                    cvss_info = cvss[0].get("cvssData", {})
                    score = cvss_info.get("baseScore", 0.0)
                    severity = cvss_info.get("baseSeverity", "UNKNOWN")

                urls = [ref.get("url") for ref in info.get("references", [])]

                return {
                    "cve_id": cve,
                    "description": desc,
                    "base_score": score,
                    "severity": severity,
                    "references": urls,
                }

        except urllib.error.HTTPError as err:
            if err.code == 403:
                if attempt < retries:
                    time.sleep(6 * (attempt + 1))
                    continue
                print(f"[!] NVD Rate limit exceeded for {cve} after {retries + 1} attempts")
            else:
                print(f"[!] HTTP Error fetching {cve}: {err.code}")
            break

        except Exception as err:
            if attempt < retries:
                time.sleep(6 * (attempt + 1))
                continue
            print(f"[!] Failed to fetch NVD data for {cve}: {err}")
            break

    return None

# Hàm báo cáo kết quả
def report_nvd(data: Dict[str, Any]):
    if not data:
        return

    from cli.views.logger import console
    console.print(f"  ● [cyan]{data['cve_id']}[/cyan]")
    console.print(f"  ├─ Severity: [yellow]{data['severity']}[/yellow] [{data['base_score']}]")

    count = len(data["references"]) if data.get("references") else 0
    console.print(f"  ├─ References: [blue]{count}[/blue] links")

    desc = data["description"]
    short = desc[:80] + "..." if len(desc) > 80 else desc
    console.print(f"  ├─ Details: {short}")
    console.print(f"  │")
    
    links = data.get("references", [])[:2] if data.get("references") else []

    if links:
        console.print(f"  ├─ [bold magenta]FIRECRAWL[/bold magenta]")

        for idx, url in enumerate(links):
            short_url = url if len(url) <= 60 else url[:60] + "..."
            char = "└─" if idx == len(links) - 1 else "├─"
            console.print(f"  │  {char} [dim]{short_url}[/dim]")
        console.print(f"  │")
            
    cve = data.get('cve_id')
    console.print(f"  └─ [bold magenta]GITHUB[/bold magenta] - {cve}")
    console.print()
