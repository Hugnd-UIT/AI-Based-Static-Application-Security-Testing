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

def render_header():
    content = "[bold cyan]SINFUL[/bold cyan]\n[dim]Benchmark Verification Suite[/dim]"
    console.print(Panel(content, box=box.ROUNDED, expand=False, padding=(1, 4)), justify="center")
    console.print()

def render_summary(projs, expected, found, no_report):
    missed = expected - found
    rate = (found / expected * 100) if expected > 0 else 0
    
    table = Table(box=box.SIMPLE_HEAVY, show_header=False)
    table.add_column("Metric", style="bold")
    table.add_column("Value", justify="right")
    
    table.add_row("Projects Evaluated", str(projs))
    if no_report > 0:
        table.add_row("Missing Reports", f"[yellow]{no_report}[/yellow]")
    table.add_row("Expected Findings", str(expected))
    table.add_row("Detected Findings", f"[green]{found}[/green]")
    table.add_row("Missed Findings", f"[red]{missed}[/red]")
    table.add_row("Detection Rate", f"{rate:.1f}%")
    
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
    table.add_column("Detected", justify="right")
    table.add_column("Rate", justify="right")
    table.add_column("Status")
    
    for stat in stats:
        name = stat["name"]
        lang = stat["lang"]
        exp = stat["expected"]
        det = stat["detected"]
        status = stat["status"]
        
        if status == "NO REPORT":
            table.add_row(name, lang, str(exp), "-", "-", "[dim]NO REPORT[/dim]")
        elif status == "INVALID REPORT":
            table.add_row(name, lang, str(exp), "-", "-", "[dim red]INVALID[/dim red]")
        else:
            rate = (det / exp * 100) if exp > 0 else 0
            table.add_row(name, lang, str(exp), f"{det}/{exp}", f"{rate:.1f}%", get_status_style(rate))
            
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
    table.add_column("Result")
    
    for d in details:
        res = "[green]✓ DETECTED[/green]" if d["detected"] else "[red]✗ MISSED[/red]"
        table.add_row(d["cwe"], d["file"], d["type"], res)
        
    console.print(table)
    console.print()

def render_verdict(expected, found):
    console.print(Text("FINAL EVALUATION", style="bold cyan"))
    rate = (found / expected * 100) if expected > 0 else 0
    status = get_status_style(rate)
    
    content = f"[bold]Ground-Truth Detection Rate:[/bold] {rate:.1f}%\n"
    content += f"Detected {found} out of {expected} expected vulnerabilities.\n\n"
    content += f"[bold]Overall Status:[/bold] {status}"
    
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
    total_det = 0
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
        
        det_count = 0
        details = []
        
        for v in vulns:
            cwe = v.get("cwe", "").upper()
            target = v.get("file", "")
            vtype = v.get("type", "")
            
            detected = False
            for flaw in findings:
                fpath = str(flaw.get("path", "")).replace("\\", "/")
                
                if target in fpath:
                    fid = str(flaw.get("id", "")).upper()
                    ftitle = str(flaw.get("title", "")).upper()
                    fmsg = str(flaw.get("message", "")).upper()
                    
                    fcwes = extract_cwes(flaw)
                    has_cwe = any(cwe in str(c).upper() for c in fcwes)
                    
                    if cwe in fid or cwe in ftitle or cwe in fmsg or vtype.upper() in ftitle or has_cwe:
                        detected = True
                        break
            
            if detected:
                det_count += 1
                
            details.append({
                "cwe": cwe,
                "file": target,
                "type": vtype,
                "detected": detected
            })
            
        total_det += det_count
        stats.append({"name": proj.name, "lang": lang, "expected": exp_count, "detected": det_count, "status": "OK"})
        projects.append({"name": proj.name, "details": details, "status": "OK"})
        
    render_summary(total_proj, total_exp, total_det, missing_count)
    
    if stats:
        render_overview(stats)
        
    for pd in projects:
        render_details(pd["name"], pd["details"], pd["status"])
        
    render_verdict(total_exp, total_det)

if __name__ == "__main__":
    verify()
