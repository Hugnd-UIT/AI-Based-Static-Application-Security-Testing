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

MODELS = [
    "deepseek/deepseek-v4-pro"
]

# Khởi tạo công cụ phân tích cú pháp Tree-sitter
def init_sitter():
    set_path = Path("src/ast/tree-sitter.py").resolve()
    load_spec = importlib.util.spec_from_file_location("ts_module", set_path)
    use_module = importlib.util.module_from_spec(load_spec)
    load_spec.loader.exec_module(use_module)

    return use_module

# Khởi chạy toàn bộ quy trình quét bảo mật
def run_scan(path, rules=None, model=None, fix=False):
    m = model or MODELS[0]
    tag = fr" [[cyan]{m}[/cyan]]"
    
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

    flaws = []
    
    try:
        ctx = use_module.build_context(str(sdir))

        if ctx:
            res["file_context"] = ctx

        else:
            ctx = ""

    except Exception:
        ctx = ""

    cache = {}

    def process_flaws(flaws, agent_name):
        if not flaws:
            return
        from cli.views.logger import console
        from rich.panel import Panel
        import textwrap
        for idx, item in enumerate(flaws):
            console.print(f"  Working [bold]{idx+1}/{len(flaws)}[/bold]")
            console.print(f"  └─ [blue]{item['path']}[/blue]")
            
            try:
                fpath = str(sdir / item["path"]) if item["path"] != str(sdir) else str(sdir)
                ast = use_module.extract_context(fpath, item["start_line"], item["end_line"], sdir=str(sdir))
    
                if ctx:
                    ast += f"\n\n[INTER-PROCEDURAL TAINT ANALYSIS]\n{ctx[:10000]}"
    
            except Exception as e:
                ast = f"Error extracting AST context: {e}"
    
                if ctx:
                    ast += f"\n\n[INTER-PROCEDURAL TAINT ANALYSIS]\n{ctx[:10000]}"
            
            item["ast"] = ast
    
            try:
                import textwrap
                logger.blank()
                
                retries = 2
                rcount = 0
                trace = {}
                
                scan = MODELS[0]
                console.print(f"  [bold magenta]● SCANNING AGENT[/bold magenta] [[cyan]{scan}[/cyan]]")

                key = (os.path.basename(item.get('path', '')).lower(), item.get('start_line', 0) // 15)
                if key in cache:
                    cached_trace, cached_verdict = cache[key]
                    console.print(f"  ├─ [dim]↩ Reusing cached scan result[/dim]")
                    item["dataflow_trace"] = json.dumps(cached_trace.get("data_flow", []), indent=2)
                    item.update(cached_verdict)
                    if cached_verdict.get("sink_file"):
                        item["path"] = cached_verdict["sink_file"]
                    continue
                
                while rcount < retries:
                    trace = scan_agents.start_scan(
                        item, ast,
                        model=MODELS[0], # Scanning Agent Role
                        target=str(sdir),
                        module=use_module,
                    )
                    
                    if trace and trace.get("data_flow"):
                        item["dataflow_trace"] = json.dumps(trace["data_flow"], indent=2)
                        hops = len(trace["data_flow"])
    
                        if trace.get("source_identified"):
                            console.print(f"  ├─ [cyan]◆ Source:[/cyan] [dim]{trace.get('source_variable', 'Unknown')}[/dim]")
                            console.print(f"  ├─ [cyan]◆ Sink:[/cyan] [dim]{trace.get('sink_function', 'Unknown')}[/dim]")
    
                            for hop in trace["data_flow"]:
                                console.print(f"  │  [dim]Hop {hop.get('step')}: {hop.get('variable')} -> {hop.get('operation')}[/dim]")
    
                        console.print(f"  └─ [bold green]✔ {hops} Hops[/bold green]")
                        break
                    
                    elif trace and trace.get("surr"):
                        surr = trace.get("surrogate_function", "Unknown")
                        item["sink_context"] = f"Original sink was unreachable. We are now treating '{surr}' as the sink. Use find_callers('{surr}') if needed."
                        rcount += 1
                        console.print(f"  ├─ [yellow]⚠ Flow broken → Surrogate: {surr} (retry {rcount}/{retries})[/yellow]")
                        
                    else:
                        item["dataflow_trace"] = "No trace available"
                        console.print(f"  └─ [bold yellow]⚠ Data flow untraceable[/bold yellow]")
                        break
                
                if rcount > retries:
                    item["dataflow_trace"] = "No trace available (max retries reached)"
                    console.print(f"  └─ [bold yellow]⚠ Data flow untraceable after {retries} retries[/bold yellow]")
    
            except Exception as e:
                console.print(f"  └─ [bold red]✖ Data Flow Tracing failed: {e}[/bold red]")
                item["dataflow_trace"] = f"Trace Error: {e}"
    
            vuln = False
    
            try:
                import textwrap
                logger.blank()
                audit = MODELS[0]
                console.print(f"  [bold magenta]● AUDITING AGENT[/bold magenta] [[cyan]{audit}[/cyan]]")
    
                verdict = audit_agents.start_audit(
                    item, ast, ctx,
                    model=MODELS[0], # Auditing Agent Role
                    target=str(sdir),
                    module=use_module,
                )
    
                verdict_str = verdict.get("verdict", "UNKNOWN").upper()
                vuln = verdict_str == "VULNERABLE"
                reason = verdict.get("reasoning", "")
    
                if reason:
                    width = max(60, console.width - 10)
    
                    for line in textwrap.wrap(reason, width=width):
                        console.print(f"  │  [dim]{line}[/dim]")
    
                conf = verdict.get("confidence", 0)
                if vuln:
                    console.print(
                        f"  ├─ [bold red]✖ VULNERABLE[/bold red]"
                    )
                    console.print(
                        f"  ├─ [dim][CVSS: {verdict.get('cvss_estimate', 'N/A')}] [{verdict.get('severity', 'UNKNOWN')}][/dim]"
                    )
                    console.print(
                        f"  ├─ [dim][Confidence: {verdict.get('confidence', 'N/A')}%][/dim]"
                    )
                    if "cwe_ids" in verdict:
                        console.print(
                            f"  ├─ [dim][CWEs: {verdict.get('cwe_ids', [])}][/dim]"
                        )
                    console.print(
                        f"  └─ [dim][Class: {verdict.get('vuln_class', 'N/A')}][/dim]"
                    )
                    res["vuln"] = True
                    vuln = True
                    
                    if "sink_file" in verdict and verdict["sink_file"]:
                        item["path"] = verdict["sink_file"]
                        console.print(f"  ├─ [dim][Sink: {item['path']}][/dim]")

                    item.update(verdict)

                    cache[key] = (trace, verdict)
    
                elif verdict_str == "SAFE":
                    console.print(
                        f"  └─ [bold green]✓ SAFE[/bold green] [dim][Confidence: {conf}%][/dim]"
                    )
                else:
                    console.print(
                        f"  └─ [bold yellow]⚠ UNKNOWN[/bold yellow]"
                    )
    
            except Exception as e:
                console.print(f"  ├─ [bold red]✖ Auditor Agent failed: {e}[/bold red]")
    
    
    
                if fix:
    
                    try:
                        logger.blank()
                        sfix = MODELS[0]
                        console.print(f"  [bold magenta]● FIXING AGENT[/bold magenta] [[cyan]{sfix}[/cyan]]")
                        from src.fix.agents import models as ufix
                        fixres = ufix.start_fix(
                            item, ast, ctx,
                            model=sfix,
                            target=str(sdir),
                            module=use_module,
                        )
                        item["fix"] = fixres
    
                        if fixres and "patches" in fixres:
    
                            if "explanation" in fixres:
                                width = max(60, console.width - 10)
    
                                for line in textwrap.wrap(fixres['explanation'], width=width):
                                    console.print(f"  │  [dim]{line}[/dim]")
    
                            for pidx, patch in enumerate(fixres["patches"]):
                                console.print(f"  │  [dim]Patch {pidx+1}: {patch.get('file_path')}[/dim]")
    
                            console.print(f"  └─ [bold green]✔ Generated {len(fixres['patches'])} patch(es)[/bold green]")
    
                        else:
                            console.print(f"  └─ [bold yellow]⚠ Failed to generate fix[/bold yellow]")
    
                    except Exception as e:
                        console.print(f"  └─ [bold red]✖ Fixer Agent failed: {e}[/bold red]")
    
            logger.blank()
    

    def sca_thread():
        from cli.views.logger import console
        sca_flaws = []
        cves = []
        parts = []
        sca_flaws = []
        if deps:
    
            try:
                cves = osv.check_osv(deps)
    
            except AttributeError:
                cves = []
    
            from src.rag import usage
            cves = usage.check_usage(str(sdir), cves, use_module)
            cves = [cve for cve in cves if cve.get("reachable", True)]
    
            res["cves"] = cves
            osv.report_osv(cves)
    
            scves = set()
    
            for cve in cves:
    
                for alias in cve.get("cve", []):
    
                    if str(alias).startswith("CVE-"):
                        scves.add(alias)
    
            if scves:
                from cli.views.logger import console as ccons
                
                def fetch_cve(ccve: str):
                    ndata = nvd.fetch_cve(ccve)
    
                    if not ndata:
                        return None
    
                    links = ndata.get("references", [])
    
                    if links:
                        ndata["firecrawl_poc"] = ""
    
                        for url in links[:2]:
                            md = firecrawl.scrape_url(url)
    
                            if md:
                                ndata["firecrawl_poc"] += f"\n\nSource: {url}\n{md}"
    
                    gh = github.search_github(ccve)
    
                    if "error" not in gh:
                        ndata["github_issues"] = gh.get("github_issues", [])
    
                    return ndata
    
                ids = list(scves)
    
                for idx, cid in enumerate(ids):
                    try:
                        nres = fetch_cve(cid)
    
                        if nres:
                            ccons.print("")
                            nvd.report_nvd(nres)
                            res["nvd"].append(nres)
                            
                    except Exception as e:
                        ccons.print(f"  [dim]Failed to fetch {cid}: {e}[/dim]")
                    
                    if idx < len(ids) - 1:
                        time.sleep(0.6)
    
        parts = []
        
        if res["nvd"] or res["cves"]:
            from cli.views.logger import console
            import textwrap
    
            pcves = []
            fnvd = {n.get("cve_id"): n for n in res.get("nvd", []) if n.get("cve_id")}
    
            for base in res.get("cves", []):
                mcve = dict(base)
                aliases = mcve.get("cve", [])
    
                for alias in aliases:
    
                    if alias in fnvd:
                        mcve.update(fnvd[alias])
                        break
    
                pcves.append(mcve)
    
            # SCA
            logger.section("SCA")
            rags = []
    
            for idx, data in enumerate(pcves):
                console.print(f"\n  [bold magenta]● RAG AGENT[/bold magenta]{tag}")
                
                jstr = json.dumps({
                    "cve_info": data,
                    "runtimes": res.get("language_versions")
                }, indent=2)
                
                try:
                    rsum = rag_agents.start_rag(jstr, model=MODELS[0]) # RAG Agent Role
                    res["rag_summaries"].append(rsum)
                    rags.append(rsum)
    
                    if "ccve" in rsum and rsum["ccve"] not in ["None", "Unknown"]:
                        console.print(f"  ├─ [cyan]◆ Analyzing {rsum['ccve']}[/cyan]")
    
                    if "attack_vector" in rsum and rsum["attack_vector"]:
                        width = max(60, console.width - 15)
    
                        for line in textwrap.wrap(str(rsum['attack_vector']), width=width, initial_indent="Vector: ", subsequent_indent="        "):
                            console.print(f"  │  [dim]{line}[/dim]")
    
                    if "mitigation" in rsum and rsum["mitigation"]:
                        width = max(60, console.width - 15)
    
                        for line in textwrap.wrap(str(rsum['mitigation']), width=width, initial_indent="Mitigation: ", subsequent_indent="            "):
                            console.print(f"  │  [dim]{line}[/dim]")
                    console.print(f"  └─ [bold green]✔ Analysis completed[/bold green]")
                
                except Exception as e:
                    console.print(f"  └─ [bold red]✖ RAG failed: {e}[/bold red]")
    
            # SAST
            console.print()
    
            for idx, rsum in enumerate(rags):
                if rsum.get("ccve") in ["None", "Unknown", None]:
                    continue
    
                try:
                    brief = {
                        "ccve": rsum.get("ccve"),
                        "dependency": rsum.get("dependency"),
                        "vulnerable_functions": rsum.get("functions", []),
                        "attack_vector": rsum.get("attack_vector"),
                    }
                    cjson = json.dumps(brief, indent=2)
                    parts.append(cjson)
                    ctx = cjson
                    
                    role = MODELS[0]
                    tstr = rsum.get("ccve", "Unknown CVE")
                    console.print(f"\n  [bold magenta]● VERIFYING AGENT[/bold magenta] [[cyan]{role}[/cyan]]")
                    console.print(f"  ├─ [cyan]◆ Target: {tstr}[/cyan]")
                    from src.rag.agents import verifier
                    poc = verifier.start_verify(ctx, model=role, target=str(sdir), module=use_module)
                    
                    exploit = poc.get("exploitable", False)
                    width = max(60, console.width - 15)
                    
                    if "error" in poc or not exploit:
                        console.print(f"  ├─ [bold yellow]⚠ Not exploitable![/bold yellow]")
    
                        if "error" in poc:
                            reason = str(poc['error']).strip()
                            lines = []
    
                            for line in reason.split('\n'):
                                lines.extend(textwrap.wrap(line, width=width) or [""])
    
                            if lines:
                                console.print(f"  │  [dim]Reason: {lines[0]}[/dim]")
    
                                for line in lines[1:]:
                                    console.print(f"  │  [dim]{line}[/dim]")
                                    
                        elif poc.get("reasoning"):
                            reason = str(poc['reasoning']).strip()
                            lines = []
    
                            for line in reason.split('\n'):
                                lines.extend(textwrap.wrap(line, width=width) or [""])
    
                            if lines:
                                console.print(f"  │  [dim]Reason: {lines[0]}[/dim]")
    
                                for line in lines[1:]:
                                    console.print(f"  │  [dim]{line}[/dim]")
                                    
                        ctx += "\nNOTE: PoC Verifier determined this CVE is NOT exploitable in the current codebase."
    
    
                    else:
                        conf = poc.get('confidence', 100)
                        console.print(f"  ├─ [bold green]✔ Exploitable! \\[Confidence: {conf}%][/bold green]")
    
                        if poc.get("reasoning"):
                            reason = str(poc['reasoning']).strip()
                            lines = []
    
                            for line in reason.split('\n'):
                                lines.extend(textwrap.wrap(line, width=width) or [""])
    
                            if lines:
                                console.print(f"  │  [dim]Reason: {lines[0]}[/dim]")
    
                                for line in lines[1:]:
                                    console.print(f"  │  [dim]{line}[/dim]")
                        
                        expand = MODELS[0]
                        console.print(f"\n  [bold magenta]● EXPANDING AGENT[/bold magenta] [[cyan]{expand}[/cyan]]")
                        console.print(f"  ├─ [cyan]◆ Target: {tstr}[/cyan]")
                        from src.rag.agents import expander
                        exp = expander.start_expand(ctx, model=expand, target=str(sdir), module=use_module)
    
                        sinks = exp.get("extra_sinks", [])
    
                        if isinstance(sinks, str):
    
                            try:
                                psinks = json.loads(sinks)
    
                                if isinstance(psinks, list):
                                    sinks = psinks
    
                                else:
                                    sinks = [{"pattern": sinks, "description": "Expanded sink"}]
    
                            except Exception:
                                sinks = [{"pattern": sinks, "description": "Expanded sink"}]
    
                        elif not isinstance(sinks, list):
                            sinks = []
                            
                        if sinks:
                            console.print(f"  ├─ [cyan]◆ Extracted {len(sinks)} new sink patterns[/cyan]")
                            from src.tools.actions import search_pattern
    
                            for sink in sinks:
    
                                if isinstance(sink, str):
                                    pat = sink
                                    desc = pat
    
                                elif isinstance(sink, dict):
                                    pat = sink.get("pattern", "")
                                    desc = sink.get("description", pat)
    
                                else:
                                    continue
                                
                                console.print(f"  │  [dim]Searching for: {pat}[/dim]")
    
                                if pat:
    
                                    try:
                                        search = search_pattern({"pattern": pat}, str(sdir))
    
                                        if search.startswith("[PATTERN"):
                                            lines = search.split("\n")[1:]
    
                                            for line in lines:
    
                                                if line.startswith("  ") and ":" in line:
                                                    parts = line.strip().split(":", 2)
    
                                                    if len(parts) >= 2:
                                                        gfile = parts[0]
    
                                                        try:
                                                            num = int(parts[1])
    
                                                        except ValueError:
                                                            num = 1
                                                        
                                                        flaw = {
                                                            "id": f"dynamic-sink-{pat}",
                                                            "message": f"Dynamically expanded sink from CVE: {desc}",
                                                            "path": gfile,
                                                            "start_line": num,
                                                            "end_line": num,
                                                            "severity": sink.get("severity", "WARNING") if isinstance(sink, dict) else "WARNING"
                                                        }
                                                        sca_flaws.append(flaw)
    
                                    except Exception as e:
                                        pass
    
                            console.print("  └─ [bold green]✔ Injected![/bold green]")
    
                        else:
                            console.print("  └─ [dim]No extra sinks![/dim]")
    
                except Exception as e:
                    console.print(f"  └─ [bold red]✖ RAG failed: {e}[/bold red]")
    
        else:
            from cli.views.logger import console
            logger.section("SCA")
            console.print(f"  [bold magenta]● RAG AGENT[/bold magenta]{tag}")
            console.print("  └─ [dim]No vulnerabilities found! Skip![/dim]")
    
        ctx = "\n\n---\n\n".join(parts) if parts else "No relevant supply chain vulnerabilities found in project dependencies."
        if cves:
            res['cves'] = cves
        process_flaws(sca_flaws, 'SCA')
        return sca_flaws, parts, ctx

    def sast_thread():
        nonlocal rules
        from cli.views.logger import console
        sgres = []
        try:
            from src.scan.agents.extractor import extract_functions
            from src.scan.agents.classifier import classify
            from src.scan.agents.generator import generate
            import os
    
            logger.section("SAST")
            console.print(f"  [bold magenta]● GENERATING AGENT[/bold magenta]")
            
            console.print("  ├─ [cyan]◆ Extracting codes...[/cyan]")
            apis = extract_functions(str(sdir))
            
            if apis:
                console.print(f"  ├─ [cyan]◆ Classifying {len(apis)} sources & sinks...[/cyan]")
                vuln_scope = "Any potential security vulnerability, including zero-days, injection flaws, logic defects, and dangerous data flows"
                classifications = classify(apis, vuln_scope)
                        
                console.print("  ├─ [cyan]◆ Generating rules...[/cyan]")
                dynamic_rule_path = generate(classifications, output=str(sdir))
                
                if dynamic_rule_path and os.path.exists(dynamic_rule_path):
                    console.print(f"  └─ [bold green]✔ Generate completed: {os.path.basename(dynamic_rule_path)}[/bold green]")
                    if rules is None:
                        from src.scan.semgrep import RULES as default_rules
                        rules = default_rules.copy()
                    elif isinstance(rules, str):
                        rules = [rules]
                    rules.append(dynamic_rule_path)
                else:
                    console.print("  └─ [dim]No rules generated[/dim]")
            else:
                console.print("  └─ [dim]No APIs extracted.[/dim]")
        except Exception as e:
            console.print(f"  └─ [bold red]✖ Generator failed: {e}[/bold red]")
    
        sgres = semgrep.scan_code(str(sdir), rules)
        
        # Inject direct vulnerabilities from classification
        if 'classifications' in locals() and classifications:
            for item in classifications:
                if item.get('type') == 'vuln':
                    sgres.append({
                        "id": f"dynamic-ai-vuln-{item.get('function')}",
                        "message": f"AI Classifier detected structural vulnerability in {item.get('function')}",
                        "path": item.get('file', ''),
                        "start_line": item.get('start_line', 1),
                        "end_line": item.get('end_line', 2),
                        "severity": "HIGH",
                        "dataflow_trace": "[DIRECT VULNERABILITY DETECTED]\nNo taint path required. Structural defect found in function body."
                    })

        # Deduplicate findings
        def deduplicate(findings):
            seen = set()
            deduped = []
            for f in findings:
                key = (f.get("path"), f.get("start_line"), f.get("message"))
                if key not in seen:
                    seen.add(key)
                    deduped.append(f)
            return deduped

        sgres = deduplicate(sgres)

        console.print(f'  └─ [bold green]✔ Scan completed: {len(sgres)} vulnerabilities[/bold green]')
        semgrep.report_scan(sgres)
        process_flaws(sgres, 'SAST')
        return sgres

    f1_res = sca_thread()
    f2_res = sast_thread()
    
    if isinstance(f1_res, tuple) and len(f1_res) == 3:
        sca_flaws, parts, ctx = f1_res
    else:
        sca_flaws = []
        
    if isinstance(f2_res, list):
        sgres = f2_res
    else:
        sgres = []

    flaws = sca_flaws + sgres
    res['findings'] = flaws

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
    cerrs = len([f for f in flaws if f.get("severity") == "ERROR"])
    cwarns = len([f for f in flaws if f.get("severity") == "WARNING"])
    cinfo = len([f for f in flaws if f.get("severity") == "INFO"])
    
    vuln = res.get("vuln", False) or cerrs > 0
    msg = "[bold red]✖ VULNERABLE[/bold red]" if vuln else "[bold green]✓ SAFE[/bold green]"

    table.add_row("Target", f"[bold]{sdir.name}[/bold]")
    table.add_row("Languages", f"[cyan]{langs}[/cyan]", "Files", f"[cyan]{files}[/cyan]")
    table.add_row("Dependencies", f"[cyan]{cdeps}[/cyan]", "Duration", f"{dur}s")
    table.add_row("", "")
    table.add_row("Findings", f"[bold]{cfinds}[/bold]")

    if cerrs > 0:
        table.add_row("[red]✖ ERROR[/red]", str(cerrs))

    if cwarns > 0:
        table.add_row("[yellow]⚠ WARNING[/yellow]", str(cwarns))

    if cinfo > 0:
        table.add_row("[green]✓ INFO[/green]", str(cinfo))
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
