import json
import subprocess
from pathlib import Path
from typing import Dict, List, Any

RULES = ["p/owasp-top-ten", "p/security-audit", "p/secrets"]

def scan(target_path: str, rule_list: List[str] = None) -> List[Dict[str, Any]]:
    dir_path = Path(target_path)

    if not dir_path.exists() or not dir_path.is_dir():
        raise ValueError(f"[!] The path is invalid: {target_path}")

    rule_list = rule_list if rule_list else RULES
    scan_cmd = ["semgrep", "scan", "--json", "--quiet"]

    for rule in rule_list:
        scan_cmd.extend(["--config", rule])

    custom_rules = Path(__file__).parent / "rules"
    if custom_rules.exists() and custom_rules.is_dir():
        scan_cmd.extend(["--config", str(custom_rules)])

    scan_cmd.append(str(dir_path))

    try:
        try:
            # First attempt: use the standard semgrep command
            cmd_result = subprocess.run(scan_cmd, capture_output=True, text=True, timeout=600)
        except (FileNotFoundError, PermissionError):
            # Fallback for Windows: bypass .ps1 Execution Policies by calling python module directly
            fallback_cmd = ["python", "-m", "semgrep"] + scan_cmd[1:]
            cmd_result = subprocess.run(fallback_cmd, capture_output=True, text=True, timeout=600)

        if not cmd_result.stdout.strip():
            return []

        json_data = json.loads(cmd_result.stdout)
        scan_findings = json_data.get("results", [])

        cleaned_findings = []
        seen_locations = set()

        for finding_item in scan_findings:
            path = finding_item.get("path")
            start_line = finding_item.get("start", {}).get("line")
            
            loc_key = f"{path}:{start_line}"
            if loc_key in seen_locations:
                continue
            seen_locations.add(loc_key)

            extra_data = finding_item.get("extra", {})
            metadata = extra_data.get("metadata", {})

            clean_item = {
                "id": finding_item.get("check_id"),
                "path": finding_item.get("path"),
                "start_line": finding_item.get("start", {}).get("line"),
                "start_col": finding_item.get("start", {}).get("col"),
                "end_line": finding_item.get("end", {}).get("line"),
                "end_col": finding_item.get("end", {}).get("col"),
                "severity": extra_data.get("severity"),
                "message": extra_data.get("message"),
                "lines": extra_data.get("lines"),
                "cwe": metadata.get("cwe", []),
                "owasp": metadata.get("owasp", []),
                "category": metadata.get("category", ""),
                "technology": metadata.get("technology", []),
                "confidence": metadata.get("confidence", ""),
                "impact": metadata.get("impact", ""),
                "likelihood": metadata.get("likelihood", ""),
                "references": metadata.get("references", []),
                "shortlink": metadata.get("shortlink", ""),
                "vulnerability_class": metadata.get("vulnerability_class", []),
                "dataflow_trace": extra_data.get("dataflow_trace"),
                "fix": extra_data.get("fix"),
                "fix_regex": extra_data.get("fix_regex")
            }

            cleaned_findings.append(clean_item)

        return cleaned_findings

    except subprocess.TimeoutExpired:
        print("[!] Semgrep scan timed out")
        return []

    except json.JSONDecodeError:
        print("[!] Failed to parse Semgrep JSON output.")
        return []

    except FileNotFoundError:
        print("[!] Semgrep is not installed or blocked. Please run: pip install semgrep")
        print("    If on Windows, ensure Execution Policies allow running scripts, or use WSL.")
        return []
        
    except PermissionError:
        print("[!] Permission denied when running Semgrep. If on Windows, try running terminal as Administrator or check Execution Policies.")
        return []

from cli.views import logger

def report(scan_findings: List[Dict[str, Any]]):
    logger.section("SEMGREP")

    from cli.views.logger import console
    if not scan_findings:
        console.print("  [green]✓ No vulnerabilities detected[/green]")
        return

    console.print(f"     [bold]{len(scan_findings)} vulnerabilities detected[/bold]")
    console.print()

    for finding_item in scan_findings:
        severity_level = finding_item["severity"]
        rule_id = finding_item["id"]
        file_path = finding_item["path"]
        line_num = finding_item["start_line"]
        
        if severity_level == "ERROR":
            console.print("  [bold red]✖ ERROR[/bold red]")
            console.print(f"  [red]├─[/red] Rule   [cyan]{rule_id}[/cyan]")
            console.print(f"  [red]├─[/red] File   [blue]{file_path}[/blue]")
            console.print(f"  [red]└─[/red] Line   [yellow]{line_num}[/yellow]")
        else:
            console.print("  [bold yellow]⚠ WARNING[/bold yellow]")
            console.print(f"  [yellow]├─[/yellow] Rule   [cyan]{rule_id}[/cyan]")
            console.print(f"  [yellow]├─[/yellow] File   [blue]{file_path}[/blue]")
            console.print(f"  [yellow]└─[/yellow] Line   [yellow]{line_num}[/yellow]")
        console.print()
