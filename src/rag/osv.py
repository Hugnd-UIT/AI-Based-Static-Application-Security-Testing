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

# Hàm kiểm tra lỗ hổng OSV
def check_osv(deps: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    if not deps:
        return []

    queries = []

    # Map hệ sinh thái của hệ thống sang hệ sinh thái của osv
    for dep in deps:
        if not dep.get("version"):
            continue

        eco = ECO.get(dep["ecosystem"], dep["ecosystem"])
        query = {
            "package": {"name": dep["package"], "ecosystem": eco},
            "version": dep["version"],
        }
        queries.append(query)

    payload = json.dumps({"queries": queries}).encode("utf-8")
    req = urllib.request.Request(URL, data=payload, headers={"Content-Type": "application/json"})

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            results = data.get("results", [])
            vulns = []

            for idx, result in enumerate(results):
                if "vulns" in result:
                    info = deps[idx]

                    for vuln in result["vulns"]:
                        aliases = vuln.get("aliases", [])

                        if not aliases and vuln.get("id", "").startswith("GHSA"):
                            try:
                                url = f"https://api.osv.dev/v1/vulns/{vuln['id']}"
                                with urllib.request.urlopen(url, timeout=10) as res:
                                    alias_data = json.loads(res.read().decode("utf-8"))
                                    aliases = alias_data.get("aliases", [])
                            except Exception:
                                pass

                        vulns.append(
                            {
                                "package": info["package"],
                                "version": info["version"],
                                "ecosystem": info["ecosystem"],
                                "vuln_id": vuln.get("id"),
                                "cve": aliases,
                                "summary": vuln.get("summary", "No summary provided"),
                                "details": vuln.get("details", ""),
                                "references": [ref.get("url") for ref in vuln.get("references", [])],
                            }
                        )

            return vulns

    except Exception as err:
        print(f"[!] Failed to connect to OSV: {err}")
        return []

from cli.views import logger

# Hàm báo cáo kết quả
def report_osv(vulns: List[Dict[str, Any]]):
    from cli.views.logger import console

    if not vulns:
        console.print("  [green]- No known vulnerabilities found in dependencies[/green]")
        return

    console.print(f"\n  [bold]{len(vulns)} vulnerabilities detected[/bold]")
    console.print()

    groups = {}

    for vuln in vulns:
        pkg = f"{vuln['package']} v{vuln['version']}"

        if pkg not in groups:
            groups[pkg] = []
        groups[pkg].append(vuln)

    for pkg, issues in groups.items():
        console.print(f"  ● [magenta]{pkg}[/magenta]")

        for idx, issue in enumerate(issues):
            cve = ", ".join(c for c in issue["cve"] if str(c).startswith("CVE"))
            text = f" [{cve}]" if cve else ""
            id = issue['vuln_id']
            summary = issue['summary'][:80] + "..." if len(issue['summary']) > 80 else issue['summary']
            
            last = (idx == len(issues) - 1)
            prefix = "  └─" if last else "  ├─"
            
            console.print(f"{prefix} [red]{id}{text}[/red]: {summary}")
        
        console.print()
