import json
import os
import time
import urllib.request
from typing import Dict, Any, Optional

URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="

def fetch(cve_id: str, retries: int = 2) -> Optional[Dict[str, Any]]:
    if not cve_id.startswith("CVE-"):
        return None

    api_url = f"{URL}{cve_id}"

    for attempt in range(retries + 1):
        try:
            api_req = urllib.request.Request(api_url)
            api_key = os.environ.get("NIST_API_KEY", "")
            if api_key:
                api_req.add_header("apiKey", api_key)
            with urllib.request.urlopen(api_req, timeout=30) as api_resp:
                json_data = json.loads(api_resp.read().decode("utf-8"))
                vuln_list = json_data.get("vulnerabilities", [])

                if not vuln_list:
                    return None

                cve_data = vuln_list[0].get("cve", {})
                desc_list = cve_data.get("descriptions", [])
                desc_text = "No description available."

                for desc_item in desc_list:
                    if desc_item.get("lang") == "en":
                        desc_text = desc_item.get("value")
                        break

                metrics_data = cve_data.get("metrics", {})
                cvss_data = metrics_data.get("cvssMetricV31", metrics_data.get("cvssMetricV30", []))

                base_score = 0.0
                severity_level = "UNKNOWN"

                if cvss_data:
                    cvss_info = cvss_data[0].get("cvssData", {})
                    base_score = cvss_info.get("baseScore", 0.0)
                    severity_level = cvss_info.get("baseSeverity", "UNKNOWN")

                ref_urls = [ref.get("url") for ref in cve_data.get("references", [])]

                return {
                    "cve_id": cve_id,
                    "description": desc_text,
                    "base_score": base_score,
                    "severity": severity_level,
                    "references": ref_urls,
                }

        except urllib.error.HTTPError as http_err:
            if http_err.code == 403:
                if attempt < retries:
                    time.sleep(6 * (attempt + 1))
                    continue
                print(f"[!] NVD API Rate Limit Exceeded for {cve_id} after {retries + 1} attempts")
            else:
                print(f"[!] HTTP Error fetching {cve_id}: {http_err.code}")
            break
        except Exception as fetch_err:
            print(f"[!] Failed to fetch NVD data for {cve_id}: {fetch_err}")
            break

    return None

def report(cve_data: Dict[str, Any]):
    if not cve_data:
        return

    from cli.views.logger import console
    console.print(f"  [magenta]NVD[/magenta] [cyan]{cve_data['cve_id']}[/cyan]")
    console.print(f"  ├─ Severity [yellow]{cve_data['severity']}[/yellow] ({cve_data['base_score']})")

    ref_count = len(cve_data["references"]) if cve_data.get("references") else 0
    console.print(f"  ├─ References [blue]{ref_count}[/blue] links")

    desc_text = cve_data["description"]
    short_desc = desc_text[:80] + "..." if len(desc_text) > 80 else desc_text
    console.print(f"  └─ Details {short_desc}")
    console.print()
