import json
import urllib.request
from typing import Dict, List, Any

from src.rag.langs import expand_before_osv, expand_after_osv

URL = "https://api.osv.dev/v1/querybatch"

ECO = {
    "npm": "npm",
    "packagist": "Packagist",
    "pypi": "PyPI",
    "maven": "Maven",
    "go": "Go",
    "rubygems": "RubyGems",
    "nuget": "NuGet",
    "crates.io": "crates.io",
    "pub": "Pub",
    "hex": "Hex",
    "vcpkg": "vcpkg",
    "conan": "Conan",
}

# Check OSV vulnerabilities
def check_osv(deps: List[Dict[str, str]], _depth: int = 0) -> List[Dict[str, Any]]:
    if not deps:
        return []

    # Expand transitive deps
    if _depth == 0:
        extra = expand_before_osv(deps)
        if extra:
            deps = deps + extra

    queries = []
    picked = []
    seen_dep = set()

    # Map ecosystems
    for dep in deps:
        if not dep.get("version"):
            continue

        # Filter duplicates
        tag = (dep["package"].lower(), dep["version"])
        
        if tag in seen_dep:
            continue
        seen_dep.add(tag)

        eco = ECO.get(dep["ecosystem"], dep["ecosystem"])
        query = {
            "package": {"name": dep["package"]},
            "version": dep["version"],
        }
        
        if eco not in ["vcpkg", "Conan"]:
            query["package"]["ecosystem"] = eco
        queries.append(query)
        picked.append(dep)

    if not queries:
        return []

    payload = json.dumps({"queries": queries}).encode("utf-8")
    req = urllib.request.Request(URL, data=payload, headers={"Content-Type": "application/json"})

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            results = data.get("results", [])
            vulns = []
            seen_cve = set()

            for idx, result in enumerate(results):
                if "vulns" in result:
                    info = picked[idx]

                    for vuln in result["vulns"]:
                        aliases = vuln.get("aliases", [])
                        
                        vid = vuln.get("id", "")
                        if vid:
                            try:
                                full_req = urllib.request.Request(f"https://api.osv.dev/v1/vulns/{vid}")
                                with urllib.request.urlopen(full_req, timeout=10) as full_resp:
                                    full_data = json.loads(full_resp.read().decode("utf-8"))
                                    vuln.update(full_data)
                                    aliases = vuln.get("aliases", [])
                            except Exception:
                                pass
                            
                        if not aliases:
                            import re as _re
                            m = _re.search(r'(CVE-\d{4}-\d+)', vid)
                            if m:
                                aliases = [m.group(1)]

                        if not aliases and vuln.get("id", "").startswith("GHSA"):
                            try:
                                url = f"https://api.osv.dev/v1/vulns/{vuln['id']}"
                                with urllib.request.urlopen(url, timeout=10) as res:
                                    alias_data = json.loads(res.read().decode("utf-8"))
                                    aliases = alias_data.get("aliases", [])
                            except Exception:
                                pass

                        # Group by CVE
                        cves = [c for c in aliases if str(c).startswith("CVE-")]
                        tag = (info["package"].lower(), cves[0] if cves else vuln.get("id"))
                        if tag in seen_cve:
                            continue
                        seen_cve.add(tag)

                        vulns.append(
                            {
                                "package": info["package"],
                                "version": info["version"],
                                "ecosystem": info["ecosystem"],
                                "vuln_id": vuln.get("id"),
                                "cve": aliases,
                                "summary": vuln.get("summary") or (vuln.get("details", "")[:100] + "..." if vuln.get("details") else "No summary provided"),
                                "details": vuln.get("details", ""),
                                "references": [ref.get("url") for ref in vuln.get("references", [])],
                            }
                        )

            # Expand meta-packages
            if _depth == 0:
                zero_deps = [picked[idx] for idx, r in enumerate(results) if not r.get("vulns")]
                extra     = expand_after_osv(zero_deps)
                if extra:
                    vulns.extend(check_osv(extra, _depth + 1))

            return vulns

    except Exception as err:
        print(f"[!] Failed to connect to OSV: {err}")
        return []

from cli.views import logger

# Report OSV results function
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
