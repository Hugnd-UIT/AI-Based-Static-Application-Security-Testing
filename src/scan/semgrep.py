import json
import subprocess
from pathlib import Path
from typing import Dict, List, Any

RULES = [
    "p/owasp-top-ten",
    "p/security-audit",
    "p/secrets",
    "p/default",
    "p/xss",
    "p/sql-injection",
    "p/command-injection",
    "p/insecure-transport",
    "p/supply-chain",
    "p/python",
    "p/django",
    "p/flask",
    "p/fastapi",
    "p/nodejs",
    "p/javascript",
    "p/typescript",
    "p/react",
    "p/java",
    "p/golang",
    "p/php",
    "p/ruby",
    "p/trailofbits",
    "p/jwt",
    "p/c",
    "p/cpp",
]

def scan_code(target_path: str, rule_list: List[str] = None) -> List[Dict[str, Any]]:
    dir_path = Path(target_path)

    if not dir_path.exists() or not dir_path.is_dir():
        raise ValueError(f"[!] The path is invalid: {target_path}")

    rule_list = rule_list if rule_list else RULES
    scan_cmd = ["semgrep", "scan", "--json", "--quiet", "--no-git-ignore"]

    for rule_name in rule_list:
        scan_cmd.extend(["--config", rule_name])

    custom_rules = Path(__file__).parent / "rules"
    if custom_rules.exists() and custom_rules.is_dir():
        scan_cmd.extend(["--config", str(custom_rules)])

    scan_cmd.append(str(dir_path))

    try:
        try:
            cmd_result = subprocess.run(scan_cmd, capture_output=True, text=True, timeout=600)
        except (FileNotFoundError, PermissionError):
            fallback_cmd = ["python", "-m", "semgrep"] + scan_cmd[1:]
            cmd_result = subprocess.run(fallback_cmd, capture_output=True, text=True, timeout=600)

        output_text = cmd_result.stdout.strip()
        if not output_text:
            return []
            
        json_start = output_text.find('{')
        if json_start != -1:
            output_text = output_text[json_start:]

        json_data = json.loads(output_text)
        scan_findings = json_data.get("results", [])

        cleaned_findings = []
        seen_locations = set()

        for finding_item in scan_findings:
            file_path = finding_item.get("path")
            start_line = finding_item.get("start", {}).get("line")
            
            loc_key = f"{file_path}:{start_line}"
            if loc_key in seen_locations:
                continue
            seen_locations.add(loc_key)

            extra_data = finding_item.get("extra", {})
            meta_data = extra_data.get("metadata", {})

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
                "cwe": meta_data.get("cwe", []),
                "owasp": meta_data.get("owasp", []),
                "category": meta_data.get("category", ""),
                "technology": meta_data.get("technology", []),
                "confidence": meta_data.get("confidence", ""),
                "impact": meta_data.get("impact", ""),
                "likelihood": meta_data.get("likelihood", ""),
                "references": meta_data.get("references", []),
                "shortlink": meta_data.get("shortlink", ""),
                "vulnerability_class": meta_data.get("vulnerability_class", []),
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
        return []
        
    except PermissionError:
        print("[!] Permission denied when running Semgrep.")
        return []

from cli.views import logger

def report_scan(scan_findings: List[Dict[str, Any]]):
    logger.section("SAST")

    from cli.views.logger import console
    if not scan_findings:
        console.print("  [green]- No vulnerabilities detected[/green]")
        return

    console.print(f"  [bold]{len(scan_findings)} vulnerabilities detected[/bold]")
    console.print()

    for finding_item in scan_findings:
        severity_level = finding_item.get("severity") or "WARNING"
        rule_id = finding_item["id"]
        file_path = finding_item["path"]
        line_num = finding_item["start_line"]

        sev_upper = severity_level.upper()
        if sev_upper in ["ERROR", "CRITICAL", "HIGH"]:
            color_str = "red"
        elif sev_upper in ["WARNING", "MEDIUM"]:
            color_str = "yellow"
        else:
            color_str = "cyan"

        console.print(f"  ┌─ [bold {color_str}]{severity_level}[/bold {color_str}]")
        console.print(f"  ├─ Rule   [cyan]{rule_id}[/cyan]")
        console.print(f"  ├─ File   [dim]{file_path}[/dim]")
        console.print(f"  └─ Line   [bold yellow]{line_num}[/bold yellow]")
        console.print()
