import argparse
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')
import shutil
import tempfile
import subprocess
import os
import stat
import json
import re
from pathlib import Path
import importlib.util
import time

from dotenv import load_dotenv
load_dotenv()

from cli.views import logger
from src.config import MODELS, SITTER, skip_sca

# Khởi tạo công cụ phân tích cú pháp Tree-sitter
def init_sitter():
    load_spec = importlib.util.spec_from_file_location("ts_module", str(SITTER))
    use_module = importlib.util.module_from_spec(load_spec)
    load_spec.loader.exec_module(use_module)

    return use_module

# Khởi chạy toàn bộ quy trình quét bảo mật
def run_scan(path, rules=None, model=None, fix=False):
    m = model or MODELS[0]

    # Đặt lại đồng hồ để thời lượng tính từ lúc bắt đầu quét
    logger.reset_timer()

    temp = None
    res = {
        "status": "processing",
        "languages": {},
        "language_versions": {},
        "dependencies": [],
        "findings": [],
        "cves": [],
        "nvd": [],
        "rag_summaries": [],
        "unverified": 0,
    }

    if path.startswith("http://") or path.startswith("https://") or path.startswith("git@"):
        print(f"\n[*] Cloning repository: {path}")
        temp = tempfile.mkdtemp(prefix="ai_scan_")
        
        try:
            subprocess.run(["git", "clone", "--depth", "1", path, temp], check=True, capture_output=True)
            sdir = Path(temp).resolve()
            
        except subprocess.CalledProcessError as e:
            msg = f"Git clone failed: {e.stderr.decode('utf-8') if e.stderr else str(e)}"
            shutil.rmtree(temp, ignore_errors=True)

            return {"status": "error", "message": msg}
            
    else:
        sdir = Path(path).resolve()

        if not sdir.exists():

            return {"status": "error", "message": f"Target directory does not exist: {sdir}"}

    try:
        from src.recognize import detector
        from src.recognize import parser as dep_parser

        from src.scan import semgrep
        from src.scan.agents import models as scan_agents
        
        from src.rag import osv
        from src.rag import nvd
        from src.rag import firecrawl
        from src.rag import github
        from src.rag.agents import models as rag_agents
        from src.audit.agents import models as audit_agents

        use_module = init_sitter()
        
    except Exception as e:

        return {"status": "error", "message": f"Failed to load modules: {e}"}

    langs = detector.detect_langs(str(sdir))
    vers = detector.get_versions(langs)
    res["languages"] = langs
    res["language_versions"] = vers
    detector.report_langs(langs, vers)

    deps = dep_parser.parse_deps(str(sdir))
    res["dependencies"] = deps
    dep_parser.report_deps(deps)

    try:
        ctx = use_module.build_context(str(sdir))

        if ctx:
            res["file_context"] = ctx

        else:
            ctx = ""

    except Exception:
        ctx = ""

    cache = {}

    from src.tools.actions import reset_memory
    reset_memory()

    from src.core.sca import run_sca
    from src.core.sast import run_sast

    # Run SCA
    if skip_sca():
        logger.section("SCA")
        logger.console.print("  [dim]Skipped by SINFUL_SKIP_SCA[/dim]")
        sca_flaws = []

    else:
        sca_flaws = run_sca(deps, sdir, use_module, res, m, cache, fix)
    
    # Run SAST
    sgres = run_sast(sdir, rules, m, ctx, use_module, cache, res, fix)

    flaws = sca_flaws + sgres
    
    # Filter out duplicates (handled by cache) and non-vulnerable findings (SAFE or UNKNOWN)
    # The audit agent only adds 'verdict': 'VULNERABLE' if it confirmed the flaw.
    final_flaws = []
    for f in flaws:
        if f.get("is_duplicate"):
            continue
        if f.get("verdict", "").upper() == "VULNERABLE":
            final_flaws.append(f)
            
    res['findings'] = final_flaws
    flaws = final_flaws

    if temp:

        def remove_readonly(func, gfile, exc):
            os.chmod(gfile, stat.S_IWRITE)
            func(gfile)
        shutil.rmtree(temp, onerror=remove_readonly)

    from rich.table import Table
    from rich.panel import Panel

    logger.blank()
    table = Table(show_header=False, box=None, padding=(0, 2))
    
    langs = len(res.get("languages", {}))
    files = sum(res.get("languages", {}).values())
    cdeps = len(res.get("dependencies", []))
    dur = logger.get_time()
    cfinds = len(flaws)

    # Count by AI-determined severity, normalizing non-standard values
    _SEV_MAP = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW",
                "ERROR": "CRITICAL", "WARNING": "MEDIUM", "INFO": "LOW"}
    def _sev(f):
        return _SEV_MAP.get(f.get("severity", "").upper(), "LOW")
    scrit  = len([f for f in flaws if _sev(f) == "CRITICAL"])
    shigh  = len([f for f in flaws if _sev(f) == "HIGH"])
    smed   = len([f for f in flaws if _sev(f) == "MEDIUM"])
    slow   = len([f for f in flaws if _sev(f) == "LOW"])
    sother = cfinds - scrit - shigh - smed - slow

    vuln = res.get("vuln", False) or cfinds > 0
    lost = res.get("unverified", 0)

    # Mất phán quyết thì chưa kết luận được, báo an toàn lúc này là dương tính giả ngược
    if vuln:
        msg = "[bold red]✖ VULNERABLE[/bold red]"

    elif lost:
        msg = "[bold yellow]⚠ INCONCLUSIVE[/bold yellow]"

    else:
        msg = "[bold green]✓ SAFE[/bold green]"

    table.add_row("Target", f"[bold]{sdir.name}[/bold]")
    table.add_row("Languages", f"[cyan]{langs}[/cyan]", "Files", f"[cyan]{files}[/cyan]")
    table.add_row("Dependencies", f"[cyan]{cdeps}[/cyan]", "Duration", f"{dur}s")
    table.add_row("", "")
    table.add_row("Vulnerabilities", f"[bold]{cfinds}[/bold]")

    if scrit > 0:
        table.add_row("[bold red]✖ CRITICAL[/bold red]", str(scrit))
    if shigh > 0:
        table.add_row("[red]✖ HIGH[/red]", str(shigh))
    if smed > 0:
        table.add_row("[yellow]⚠ MEDIUM[/yellow]", str(smed))
    if slow > 0:
        table.add_row("[green]✓ LOW[/green]", str(slow))
    if sother > 0:
        table.add_row("[dim]? UNKNOWN[/dim]", str(sother))

    if lost > 0:
        table.add_row("[yellow]⚠ Unverified[/yellow]", str(lost))
    table.add_row("", "")
    table.add_row("Status", msg)

    panel = Panel(table, title="[bold]SCAN SUMMARY[/bold]", expand=False, border_style="dim")
    logger.console.print(panel)
    logger.blank()

    def ccvss(val):
        try:

            return float(val.get("cvss_estimate", 0))

        except (TypeError, ValueError):

            return 0.0

    flaws.sort(key=ccvss, reverse=True)
    res["findings"] = flaws

    return {"status": "success", "data": res}



# Khởi động ứng dụng CLI hoặc quét thư mục
def start_app():
    parser = argparse.ArgumentParser(description="Sinful AI-Based SAST")
    parser.add_argument("target", nargs="?", help="Target directory OR Git URL to scan")
    args = parser.parse_args()

    # Nếu không có target, mở giao diện dòng lệnh
    if not args.target:
        from cli.main import start_cli
        start_cli()
        return

    # Nếu có target, chạy quét trực tiếp
    res = run_scan(args.target, None, None)

    if res["status"] == "error":
        print(res["message"])
        sys.exit(1)

# Điểm vào chính của chương trình
if __name__ == "__main__":
    start_app()
