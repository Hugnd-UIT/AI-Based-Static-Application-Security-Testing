import sys
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

import os
import glob
import json
from pathlib import Path

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich import box
except ImportError as e:
    print(f"Error: Unable to import required libraries. {e}")
    sys.exit(1)

console = Console()

import sys
project_root = str(Path(__file__).resolve().parent.parent)
if project_root not in sys.path:
    sys.path.append(project_root)

def ai_judge(expected_cwe, expected_type, ai_title, ai_msg, ai_class, ai_cwes):
    try:
        from src.llm import fetch_llm
        prompt = f"""
            You are a vulnerability verification judge. 
            The benchmark EXPECTED this vulnerability: CWE: {expected_cwe}, Type: {expected_type}
            The AI scanner FOUND this vulnerability on the exact same file:
            - Title: {ai_title}
            - Message: {ai_msg}
            - Class: {ai_class}
            - Extracted CWEs: {ai_cwes}

            Determine if the AI's finding correctly describes or is a variant of the expected vulnerability.
            Return a JSON object with exactly one boolean field "match".
            Example: {{"match": true}} or {{"match": false}}
        """
        res = fetch_llm(prompt=prompt, model=None, jfmt=True)
        return res.get("match", False)
    except Exception as e:
        return False

def render_header():
    content = "[bold cyan]SINFUL[/bold cyan]\n[dim]Benchmark Verification Suite[/dim]"
    console.print(Panel(content, box=box.ROUNDED, expand=False, padding=(1, 4)), justify="center")
    console.print()

def render_summary(projs, expected, found_rule, found_ai, no_report):
    missed_rule = expected - found_rule
    rate_rule = (found_rule / expected * 100) if expected > 0 else 0
    missed_ai = expected - found_ai
    rate_ai = (found_ai / expected * 100) if expected > 0 else 0
    
    table = Table(box=box.SIMPLE_HEAVY, show_header=False)
    table.add_column("Metric", style="bold")
    table.add_column("Value", justify="right")
    
    table.add_row("Projects Evaluated", str(projs))
    if no_report > 0:
        table.add_row("Missing Reports", f"[yellow]{no_report}[/yellow]")
    table.add_row("Expected Findings", str(expected))
    table.add_row("Detected (Script Match)", f"[green]{found_rule}[/green]")
    table.add_row("Missed (Script Match)", f"[red]{missed_rule}[/red]")
    table.add_row("Detection Rate (Script Match)", f"{rate_rule:.1f}%")
    table.add_row("Detected (AI Match)", f"[green]{found_ai}[/green]")
    table.add_row("Missed (AI Match)", f"[red]{missed_ai}[/red]")
    table.add_row("Detection Rate (AI Match)", f"{rate_ai:.1f}%")
    
    console.print(Text("BENCHMARK SUMMARY", style="bold cyan"))
    console.print(table)
    console.print()

def get_status_style(rate):
    if rate >= 80:
        return "[bold green]PASS[/bold green]"
    elif rate >= 50:
        return "[bold yellow]PARTIAL[/bold yellow]"
    return "[bold red]FAIL[/bold red]"

def render_overview(stats):
    console.print(Text("PROJECT OVERVIEW", style="bold cyan"))
    table = Table(box=box.MINIMAL, header_style="bold dim")
    table.add_column("Project")
    table.add_column("Language")
    table.add_column("Expected", justify="right")
    table.add_column("Det(Script)", justify="right")
    table.add_column("Det(AI)", justify="right")
    table.add_column("Rate(Script)", justify="right")
    table.add_column("Rate(AI)", justify="right")
    table.add_column("Status")
    
    for stat in stats:
        name = stat["name"]
        lang = stat["lang"]
        exp = stat["expected"]
        det_rule = stat["det_rule"]
        det_ai = stat["det_ai"]
        status = stat["status"]
        
        if status == "NO REPORT":
            table.add_row(name, lang, str(exp), "-", "-", "-", "-", "[dim]NO REPORT[/dim]")
        elif status == "INVALID REPORT":
            table.add_row(name, lang, str(exp), "-", "-", "-", "-", "[dim red]INVALID[/dim red]")
        else:
            rate_rule = (det_rule / exp * 100) if exp > 0 else 0
            rate_ai = (det_ai / exp * 100) if exp > 0 else 0
            final_status = get_status_style(rate_rule)
            table.add_row(name, lang, str(exp), f"{det_rule}/{exp}", f"{det_ai}/{exp}", f"{rate_rule:.1f}%", f"{rate_ai:.1f}%", final_status)
            
    console.print(table)
    console.print()

def render_details(name, details, status):
    console.print(Text(f"FINDINGS: {name}", style="bold cyan"))
    if status == "NO REPORT":
        console.print("  [dim]⚠ NO REPORT[/dim]")
        console.print()
        return
    elif status == "INVALID REPORT":
        console.print("  [dim red]⚠ INVALID REPORT[/dim red]")
        console.print()
        return
        
    table = Table(box=box.SIMPLE, header_style="bold dim")
    table.add_column("CWE")
    table.add_column("Target File", overflow="fold")
    table.add_column("Vulnerability Type")
    table.add_column("Script Match")
    table.add_column("AI Match")
    
    for d in details:
        res_rule = "[green]✓[/green]" if d["det_rule"] else "[red]✗[/red]"
        res_ai = "[green]✓[/green]" if d["det_ai"] else "[red]✗[/red]"
        table.add_row(d["cwe"], d["file"], d["type"], res_rule, res_ai)
        
    console.print(table)
    console.print()

def render_verdict(expected, found_rule, found_ai):
    console.print(Text("FINAL EVALUATION", style="bold cyan"))
    rate_rule = (found_rule / expected * 100) if expected > 0 else 0
    rate_ai = (found_ai / expected * 100) if expected > 0 else 0
    
    content = f"[bold]Script Match Detection Rate:[/bold] {rate_rule:.1f}%\n"
    content += f"Detected {found_rule} out of {expected} expected vulnerabilities.\n\n"
    content += f"[bold]AI Match Detection Rate:[/bold] {rate_ai:.1f}%\n"
    content += f"Detected {found_ai} out of {expected} expected vulnerabilities.\n\n"
    content += f"[bold]Script Match Status:[/bold] {get_status_style(rate_rule)}\n"
    content += f"[bold]AI Match Status:[/bold] {get_status_style(rate_ai)}"
    
    console.print(Panel(content, box=box.ROUNDED, expand=False, border_style="cyan"))

def extract_cwes(flaw):
    cwes = flaw.get("cwe", [])
    if isinstance(cwes, str):
        cwes = [cwes]
    elif not isinstance(cwes, list):
        cwes = []
        
    meta = flaw.get("metadata", {})
    mcwe = meta.get("cwe", [])
    if isinstance(mcwe, str):
        cwes.append(mcwe)
    elif isinstance(mcwe, list):
        cwes.extend(mcwe)
        
    return cwes

def verify():
    root = Path(__file__).resolve().parent
    
    render_header()
    
    total_exp = 0
    total_det_rule = 0
    total_det_ai = 0
    total_proj = 0
    missing_count = 0
    
    stats = []
    projects = []
    
    global_findings = []
    root_reports = root.parent / "reports"
    if root_reports.exists():
        gfiles = glob.glob(str(root_reports / "sinful_report_*.json"))
        if gfiles:
            glatest = max(gfiles, key=os.path.getmtime)
            try:
                with open(glatest, "r", encoding="utf-8") as f:
                    gscan = json.load(f)
                    global_findings = gscan.get("data", {}).get("findings", []) if "data" in gscan else gscan.get("findings", [])
            except Exception:
                pass
    
    for proj in root.iterdir():
        if not proj.is_dir():
            continue
            
        tfile = proj / "vulnerabilities.json"
        if not tfile.exists():
            continue
            
        with open(tfile, "r", encoding="utf-8") as f:
            truth = json.load(f)
            
        vulns = truth.get("expected", [])
        if not vulns:
            continue
            
        total_proj += 1
        lang = truth.get("language", "unknown")
        exp_count = len(vulns)
        total_exp += exp_count
        
        rdir = proj / "reports"
        rfiles = glob.glob(str(rdir / "sinful_report_*.json")) if rdir.exists() else []
        
        findings = []
        if rfiles:
            latest = max(rfiles, key=os.path.getmtime)
            try:
                with open(latest, "r", encoding="utf-8") as f:
                    lscan = json.load(f)
                    findings = lscan.get("data", {}).get("findings", []) if "data" in lscan else lscan.get("findings", [])
            except Exception:
                stats.append({"name": proj.name, "lang": lang, "expected": exp_count, "detected": 0, "status": "INVALID REPORT"})
                projects.append({"name": proj.name, "details": [], "status": "INVALID REPORT"})
                continue
        elif global_findings:
            proj_marker = f"/benchmark/{proj.name}/"
            findings = [f for f in global_findings if proj_marker in str(f.get("path", "")).replace("\\", "/")]
        else:
            stats.append({"name": proj.name, "lang": lang, "expected": exp_count, "detected": 0, "status": "NO REPORT"})
            projects.append({"name": proj.name, "details": [], "status": "NO REPORT"})
            missing_count += 1
            continue
        
        det_count_rule = 0
        det_count_ai = 0
        details = []
        
        for v in vulns:
            cwe = v.get("cwe", "").upper()
            target = v.get("file", "")
            vtype = v.get("type", "")
            
            det_rule = False
            det_ai = False
            for flaw in findings:
                fpath = str(flaw.get("path", "")).replace("\\", "/")
                
                if target in fpath:
                    fid = str(flaw.get("id", "")).upper()
                    ftitle = str(flaw.get("title", "")).upper()
                    fmsg = str(flaw.get("message", "")).upper()
                    
                    fcwes = extract_cwes(flaw)
                    cwe_ids = flaw.get("cwe_ids", [])
                    cwe_id_match = any(cwe == f"CWE-{c_id}" for c_id in cwe_ids) if isinstance(cwe_ids, list) else False
                    has_cwe = cwe_id_match or any(cwe in str(c).upper() for c in fcwes)
                    fvuln_class = str(flaw.get("vuln_class", "")).upper()
                    
                    if not det_rule and (cwe in fid or cwe in ftitle or cwe in fmsg or vtype.upper() in ftitle or has_cwe or cwe in fvuln_class or vtype.upper() in fvuln_class):
                        det_rule = True
                        
                    if not det_ai:
                        ai_result = ai_judge(cwe, vtype, ftitle, fmsg, fvuln_class, cwe_ids)
                        if ai_result:
                            det_ai = True
                            
                    if det_rule and det_ai:
                        break
            
            if det_rule:
                det_count_rule += 1
            if det_ai:
                det_count_ai += 1
                
            details.append({
                "cwe": cwe,
                "file": target,
                "type": vtype,
                "det_rule": det_rule,
                "det_ai": det_ai
            })
            
        total_det_rule += det_count_rule
        total_det_ai += det_count_ai
        stats.append({"name": proj.name, "lang": lang, "expected": exp_count, "det_rule": det_count_rule, "det_ai": det_count_ai, "status": "OK"})
        projects.append({"name": proj.name, "details": details, "status": "OK"})
        
    render_summary(total_proj, total_exp, total_det_rule, total_det_ai, missing_count)
    
    if stats:
        render_overview(stats)
        
    for pd in projects:
        render_details(pd["name"], pd["details"], pd["status"])
        
    render_verdict(total_exp, total_det_rule, total_det_ai)

if __name__ == "__main__":
    verify()
