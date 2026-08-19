import json
import urllib.request
from typing import Dict, List, Any

URL = "https://api.osv.dev/v1/querybatch"

ECO = {
    "npm": "npm",
    "packagist": "Packagist",
    "pypi": "PyPI",
    "maven": "Maven",
    "go": "Go",
    "rubygems": "RubyGems",
    "nuget": "NuGet",
}

def check_osv_vulns(parsed_deps: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    if not parsed_deps:
        return []

    query_list = []

    for dep_item in parsed_deps:
        ecosystem_name = ECO.get(dep_item["ecosystem"], dep_item["ecosystem"])
        query_dict = {
            "package": {"name": dep_item["package"], "ecosystem": ecosystem_name},
            "version": dep_item["version"],
        }
        query_list.append(query_dict)

    payload_data = json.dumps({"queries": query_list}).encode("utf-8")
    api_req = urllib.request.Request(URL, data=payload_data, headers={"Content-Type": "application/json"})

    try:
        with urllib.request.urlopen(api_req, timeout=30) as api_resp:
            json_data = json.loads(api_resp.read().decode("utf-8"))
            results_list = json_data.get("results", [])
            vuln_list = []

            for loop_idx, result_item in enumerate(results_list):
                if "vulns" in result_item:
                    pkg_info = parsed_deps[loop_idx]

                    for vuln_item in result_item["vulns"]:
                        alias_list = vuln_item.get("aliases", [])

                        if not alias_list and vuln_item.get("id", "").startswith("GHSA"):
                            try:
                                api_url = f"https://api.osv.dev/v1/vulns/{vuln_item['id']}"
                                with urllib.request.urlopen(api_url, timeout=10) as alias_resp:
                                    alias_data = json.loads(alias_resp.read().decode("utf-8"))
                                    alias_list = alias_data.get("aliases", [])
                            except Exception:
                                pass

                        vuln_list.append(
                            {
                                "package": pkg_info["package"],
                                "version": pkg_info["version"],
                                "ecosystem": pkg_info["ecosystem"],
                                "vuln_id": vuln_item.get("id"),
                                "cve": alias_list,
                                "summary": vuln_item.get("summary", "No summary provided"),
                                "details": vuln_item.get("details", ""),
                                "references": [ref.get("url") for ref in vuln_item.get("references", [])],
                            }
                        )
            return vuln_list
    except Exception as api_err:
        print(f"[!] Failed to connect to OSV API: {api_err}")
        return []

from cli.views import logger

def report_osv(vuln_list: List[Dict[str, Any]]):
    logger.section("OSV")

    from cli.views.logger import console
    if not vuln_list:
        console.print("  [green]- No known vulnerabilities found in dependencies[/green]")
        return

    console.print(f"  [bold]{len(vuln_list)} vulnerabilities detected[/bold]")
    console.print()

    vuln_groups = {}

    for vuln_item in vuln_list:
        pkg_name = f"{vuln_item['package']} v{vuln_item['version']}"
        if pkg_name not in vuln_groups:
            vuln_groups[pkg_name] = []
        vuln_groups[pkg_name].append(vuln_item)

    for pkg_name, issue_list in vuln_groups.items():
        console.print(f"  - [magenta]{pkg_name}[/magenta]")

        for loop_idx, issue_item in enumerate(issue_list):
            cve_str = ", ".join(c for c in issue_item["cve"] if str(c).startswith("CVE"))
            display_cve = f" [{cve_str}]" if cve_str else ""
            vuln_id = issue_item['vuln_id']
            summary_text = issue_item['summary'][:80] + "..." if len(issue_item['summary']) > 80 else issue_item['summary']
            
            is_last = (loop_idx == len(issue_list) - 1)
            display_prefix = "  -" if is_last else "  |"
            
            console.print(f"{display_prefix} [red]{vuln_id}{display_cve}[/red]: {summary_text}")
        
        console.print()
