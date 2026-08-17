import sys
import os
import argparse
import json
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.append(str(ROOT_DIR))

try:
    from main import run_sast
    from cli.views import logger
    from rich.panel import Panel
except ImportError:
    print("Error: Cannot import the main module of Sinful SAST.")
    sys.exit(1)

def gen_report(scan_findings, output_path):
    sarif_rules = {}
    sarif_results = []
    
    for finding_item in scan_findings:
        rule_id = finding_item.get("check_id") or finding_item.get("rule_id", "VULN-001")
        if rule_id not in sarif_rules:
            sarif_rules[rule_id] = {
                "id": rule_id,
                "shortDescription": {"text": finding_item.get("title") or rule_id},
                "fullDescription": {"text": finding_item.get("description", "Security vulnerability detected.")},
                "defaultConfiguration": {"level": "error" if finding_item.get("severity") == "ERROR" else "warning"}
            }
        
        file_path = finding_item.get("path") or finding_item.get("file", "unknown")
        line_num = finding_item.get("start") or finding_item.get("line") or getattr(finding_item.get("start"), "line", 1)
        if isinstance(line_num, dict):
            line_num = line_num.get("line", 1)
            
        sarif_result = {
            "ruleId": rule_id,
            "level": "error" if finding_item.get("severity") == "ERROR" else "warning",
            "message": {"text": finding_item.get("extra", {}).get("message") or finding_item.get("message", "Vulnerability found")},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": file_path},
                        "region": {"startLine": line_num}
                    }
                }
            ]
        }
        sarif_results.append(sarif_result)
        
    sarif_data = {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Sinful SAST",
                        "informationUri": "https://github.com/Hugnd-UIT/AI-Based-Static-Application-Security-Testing",
                        "rules": list(sarif_rules.values())
                    }
                },
                "results": sarif_results
            }
        ]
    }
    
    with open(output_path, "w", encoding="utf-8") as output_file:
        json.dump(sarif_data, output_file, indent=2)

def start_ci():
    cli_parser = argparse.ArgumentParser(description="Sinful SAST CI Scanner")
    cli_parser.add_argument("--exit-code", type=int, default=1, help="Exit code when vulnerabilities are found")
    cli_parser.add_argument("--severity", type=str, default="ERROR,WARNING", help="Comma-separated severities to block on")
    cli_parser.add_argument("--format", type=str, default="table", choices=["table", "sarif"], help="Output format")
    cli_parser.add_argument("--output", type=str, default="results.sarif", help="Output file path for sarif")
    cli_args = cli_parser.parse_args()

    if cli_args.format != "sarif":
        logger.console.print()
        logger.console.print(Panel(
            "[bold cyan]SINFUL SAST · CI[/bold cyan]\n[dim]Continuous Integration[/dim]", 
            border_style="cyan", 
            expand=False
        ))
        logger.console.print()
    

    target_dir = os.getcwd()
    
    try:
        scan_result = run_sast(target_dir)
    except Exception as scan_err:
        if cli_args.format != "sarif":
            logger.console.print("[cyan]━━━ CI WORKFLOW ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/cyan]\n")
            logger.console.print(f"[red]✖ Exception occurred during scanning: {scan_err}[/red]\n")
        sys.exit(1)

    if scan_result.get("status") == "error":
        if cli_args.format != "sarif":
            logger.console.print("[cyan]━━━ CI WORKFLOW ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/cyan]\n")
            logger.console.print(f"[red]✖ Scan failed: {scan_result.get('message')}[/red]\n")
        sys.exit(1)

    scan_data = scan_result.get("data", {})
    scan_findings = scan_data.get("findings", [])
    
    if cli_args.format == "sarif":
        gen_report(scan_findings, cli_args.output)
        print(f"SARIF report generated: {cli_args.output}")
    
    blocked_severities = [severity_item.strip().upper() for severity_item in cli_args.severity.split(",")]
    count_blocked = len([find_item for find_item in scan_findings if find_item.get("severity", "ERROR") in blocked_severities])
    is_vulnerable = count_blocked > 0

    if cli_args.format != "sarif":
        logger.console.print("[cyan]━━━ CI WORKFLOW ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/cyan]\n")
        logger.console.print("Environment     [green]✓ VERIFIED[/green]")
        logger.console.print("Security Scan   [green]✓ COMPLETED[/green]")
        
        if is_vulnerable:
            logger.console.print(f"Findings        [red]✖ {count_blocked}[/red]")
            logger.console.print("Security Gate   [red]✖ FAILED[/red]\n")
            logger.console.print("[cyan]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/cyan]\n")
            logger.console.print("[bold red]✖ CI WORKFLOW FAILED[/bold red]\n")
            
            # Detailed findings summary
            logger.console.print(f"{count_blocked} issue(s) matched the configured severity threshold.")
            logger.console.print("Pipeline blocked.\n")
            logger.console.print(f"[dim]Exit code: {cli_args.exit_code}[/dim]")
            sys.exit(cli_args.exit_code)
        else:
            logger.console.print("Findings        [green]✓ 0[/green]")
            logger.console.print("Security Gate   [green]✓ PASSED[/green]\n")
            logger.console.print("[cyan]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/cyan]\n")
            logger.console.print("[bold green]✓ CI WORKFLOW PASSED[/bold green]\n")
            logger.console.print("No issues matched the configured severity threshold.\n")
            logger.console.print("[dim]Exit code: 0[/dim]")
            sys.exit(0)

if __name__ == "__main__":
    start_ci()
