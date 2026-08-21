import argparse
import sys
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
    "deepseek/deepseek-v4-pro",
    "mistralai/codestral-2508",
    "minimax/minimax-m2.7",
    "xiaomi/mimo-v2.5-pro",
    "mistralai/mistral-large-2512"
]

def init_sitter():
    set_path = Path("src/audit/tree-sitter.py").resolve()
    load_spec = importlib.util.spec_from_file_location("ts_module", set_path)
    use_module = importlib.util.module_from_spec(load_spec)
    load_spec.loader.exec_module(use_module)

    return use_module

def run_scan(scan_path, scan_rules=None, use_model=None, do_fix=False):
    set_model = use_model or MODELS[0]
    show_tag = fr" [[cyan]{set_model}[/cyan]]"
    
    make_dir = None
    get_result = {
        "status": "processing",
        "languages": {},
        "language_versions": {},
        "dependencies": [],
        "findings": [],
        "cves": [],
        "get_nvd": [],
        "rag_summaries": [],
    }

    if scan_path.startswith("http://") or scan_path.startswith("https://") or scan_path.startswith("git@"):
        print(f"\n[*] Cloning repository: {scan_path}")
        make_dir = tempfile.mkdtemp(prefix="ai_scan_")
        
        try:
            subprocess.run(["git", "clone", "--depth", "1", scan_path, make_dir], check=True, capture_output=True)
            scan_dir = Path(make_dir).resolve()
            
        except subprocess.CalledProcessError as catch_clone:
            show_error = f"Git clone failed: {catch_clone.stderr.decode('utf-8') if catch_clone.stderr else str(catch_clone)}"
            shutil.rmtree(make_dir, ignore_errors=True)

            return {"status": "error", "message": show_error}
            
    else:
        scan_dir = Path(scan_path).resolve()

        if not scan_dir.exists():

            return {"status": "error", "message": f"Target directory does not exist: {scan_dir}"}

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
        
    except Exception as catch_load:

        return {"status": "error", "message": f"Failed to load modules: {catch_load}"}

    count_langs = detector.detect_langs(str(scan_dir))
    get_versions = detector.get_versions(count_langs)
    get_result["languages"] = count_langs
    get_result["language_versions"] = get_versions
    detector.report_langs(count_langs, get_versions)

    parse_deps = dep_parser.parse_deps(str(scan_dir))
    get_result["dependencies"] = parse_deps
    dep_parser.report_deps(parse_deps)

    find_flaws = []
    
    try:
        build_context = use_module.build_context(str(scan_dir))

        if build_context:
            get_result["file_context"] = build_context

        else:
            build_context = ""

    except Exception:
        build_context = ""



    if build_context:
        taint_blocks = [b for b in build_context.split("[CROSS-FILE TAINT PATH DETECTED]") if b.strip()]
        for taint_block in taint_blocks:
            if "Propagates to" not in taint_block: continue
            prop_match = re.search(r"Propagates to\s*:\s*(\S+)\s*\(line (\d+)\)", taint_block)
            taint_file = prop_match.group(1) if prop_match else str(scan_dir)
            taint_line = int(prop_match.group(2)) if prop_match else 1
            
            full_path = str(scan_dir)
            if prop_match:
                for root, _, files in os.walk(str(scan_dir)):
                    if taint_file in files:
                        full_path = os.path.join(root, taint_file)
                        break
                        
            find_flaws.append({
                "id": "sinful-cross-file-taint",
                "path": full_path,
                "start_line": taint_line,
                "end_line": taint_line + 5,
                "severity": "HIGH",
                "message": "Cross-file taint path detected by inter-procedural analysis.",
                "lines": "",
                "cwe": [],
                "dataflow_trace": "[CROSS-FILE TAINT PATH DETECTED]" + taint_block.rstrip(),
            })
            
        if find_flaws:
            get_result["findings"] = find_flaws

    if parse_deps:

        try:
            list_cves = osv.check_vulns(parse_deps)

        except AttributeError:
            list_cves = []

        from src.rag import usage
        list_cves = usage.check_usage(str(scan_dir), list_cves, use_module)
        list_cves = [use_cve for use_cve in list_cves if use_cve.get("reachable", True)]

        get_result["cves"] = list_cves
        osv.report_osv(list_cves)

        get_cves = set()

        for use_cve in list_cves:

            for get_alias in use_cve.get("cve", []):

                if str(get_alias).startswith("CVE-"):
                    get_cves.add(get_alias)

        if get_cves:
            from cli.views.logger import console as cve_console
            
            def fetch_cve(check_cve: str):
                get_nvd = nvd.fetch_cve(check_cve)

                if not get_nvd:
                    return None

                get_links = get_nvd.get("references", [])

                if get_links:
                    get_nvd["firecrawl_poc"] = ""

                    for use_url in get_links[:2]:
                        get_md = firecrawl.scrape_url(use_url)

                        if get_md:
                            get_nvd["firecrawl_poc"] += f"\n\nSource: {use_url}\n{get_md}"

                get_github = github.search_issues(check_cve)

                if "error" not in get_github:
                    get_nvd["github_issues"] = get_github.get("github_issues", [])

                return get_nvd

            list_ids = list(get_cves)

            for get_index, use_cid in enumerate(list_ids):
                try:
                    nvd_result = fetch_cve(use_cid)

                    if nvd_result:
                        cve_console.print("")
                        nvd.report_nvd(nvd_result)
                        get_result["get_nvd"].append(nvd_result)
                        
                except Exception as catch_future:
                    cve_console.print(f"  [dim]Failed to fetch {use_cid}: {catch_future}[/dim]")
                
                if get_index < len(list_ids) - 1:
                    time.sleep(0.6)

    get_parts = []
    
    if get_result["get_nvd"] or get_result["cves"]:
        from cli.views.logger import console
        logger.section("SCA")
        import textwrap

        process_cves = []
        find_nvd = {n.get("check_cve"): n for n in get_result.get("get_nvd", [])}

        for get_base in get_result.get("cves", []):
            merge_cve = dict(get_base)
            get_aliases = merge_cve.get("cve", [])

            for use_alias in get_aliases:

                if use_alias in find_nvd:
                    merge_cve.update(find_nvd[use_alias])
                    break

            process_cves.append(merge_cve)

        # Loop 1: SCA (RAG Agents)
        get_rags = []

        for get_idx, get_data in enumerate(process_cves):
            console.print(f"\n  [bold magenta]● RAG AGENT[/bold magenta]{show_tag}")
            
            get_str = json.dumps({
                "cve_info": get_data,
                "runtimes": get_result.get("language_versions")
            }, indent=2)
            
            try:
                get_summary = rag_agents.start_rag(get_str, use_model=MODELS[0]) # RAG Agent Role
                get_result["rag_summaries"].append(get_summary)
                get_rags.append(get_summary)

                if "check_cve" in get_summary and get_summary["check_cve"] not in ["None", "Unknown"]:
                    console.print(f"  ├─ [cyan]◆ Analyzing {get_summary['check_cve']}[/cyan]")

                if "attack_vector" in get_summary and get_summary["attack_vector"] not in ["None", "Unknown"]:
                    set_width = max(60, console.width - 15)

                    for get_line in textwrap.wrap(get_summary['attack_vector'], width=set_width, initial_indent="Vector: ", subsequent_indent="        "):
                        console.print(f"  │  [dim]{get_line}[/dim]")

                if "mitigation" in get_summary and get_summary["mitigation"] not in ["None", "Unknown"]:
                    set_width = max(60, console.width - 15)

                    for get_line in textwrap.wrap(get_summary['mitigation'], width=set_width, initial_indent="Mitigation: ", subsequent_indent="            "):
                        console.print(f"  │  [dim]{get_line}[/dim]")
                console.print(f"  └─ [bold green]✔ Analysis completed[/bold green]")
            
            except Exception as catch_rag:
                console.print(f"  └─ [bold red]✖ RAG failed: {catch_rag}[/bold red]")

        # Loop 2: SAST (Verifier and Expander)
        logger.section("SAST")

        for use_idx, get_summary in enumerate(get_rags):

            try:
                get_brief = {
                    "check_cve": get_summary.get("check_cve"),
                    "dependency": get_summary.get("dependency"),
                    "vulnerable_functions": get_summary.get("functions", []),
                    "attack_vector": get_summary.get("attack_vector"),
                }
                cve_json = json.dumps(get_brief, indent=2)
                get_parts.append(cve_json)
                get_context = cve_json
                
                set_role = MODELS[1] # Codestral for Verifier
                set_str = get_summary.get("check_cve", "Unknown CVE")
                console.print(f"\n  [bold magenta]● VERIFYING AGENT[/bold magenta] [[cyan]{set_role}[/cyan]]")
                console.print(f"  ├─ [cyan]◆ Target: {set_str}[/cyan]")
                from src.rag.agents import verifier
                get_poc = verifier.start_verify(get_context, use_model=set_role, scan_dir=str(scan_dir), use_module=use_module) # Verifier Agent Role
                
                check_exploit = get_poc.get("exploitable", False)
                set_width = max(60, console.width - 15)
                
                if "error" in get_poc or not check_exploit:
                    console.print(f"  ├─ [bold yellow]⚠ Not exploitable![/bold yellow]")

                    if "error" in get_poc:
                        get_reason = str(get_poc['error']).strip()
                        wrap_lines = []

                        for line in get_reason.split('\n'):
                            wrap_lines.extend(textwrap.wrap(line, width=set_width) or [""])

                        if wrap_lines:
                            console.print(f"  │  [dim]Reason: {wrap_lines[0]}[/dim]")

                            for use_line in wrap_lines[1:]:
                                console.print(f"  │  [dim]{use_line}[/dim]")
                    get_context += "\nNOTE: PoC Verifier determined this CVE is NOT exploitable in the current codebase."

                else:
                    get_conf = get_poc.get('confidence', 100)
                    console.print(f"  ├─ [bold green]✔ Exploitable! \\[Confidence: {get_conf}%][/bold green]")

                    if get_poc.get("reasoning"):
                        get_reason = str(get_poc['reasoning']).strip()
                        wrap_lines = []

                        for line in get_reason.split('\n'):
                            wrap_lines.extend(textwrap.wrap(line, width=set_width) or [""])

                        if wrap_lines:
                            console.print(f"  │  [dim]Reason: {wrap_lines[0]}[/dim]")

                            for use_line in wrap_lines[1:]:
                                console.print(f"  │  [dim]{use_line}[/dim]")
                    
                    set_expand = MODELS[2] # MiniMax M2.5 for Expander
                    console.print(f"\n  [bold magenta]● EXPANDING AGENT[/bold magenta] [[cyan]{set_expand}[/cyan]]")
                    console.print(f"  ├─ [cyan]◆ Target: {set_str}[/cyan]")
                    from src.rag.agents import expander
                    get_expand = expander.start_expand(get_context, use_model=set_expand, scan_dir=str(scan_dir), use_module=use_module) # Expander Agent Role

                    get_sinks = get_expand.get("get_sinks", [])

                    if isinstance(get_sinks, str):

                        try:
                            parse_sinks = json.loads(get_sinks)

                            if isinstance(parse_sinks, list):
                                get_sinks = parse_sinks

                            else:
                                get_sinks = [{"pattern": get_sinks, "description": "Expanded sink"}]

                        except Exception:
                            get_sinks = [{"pattern": get_sinks, "description": "Expanded sink"}]

                    elif not isinstance(get_sinks, list):
                        get_sinks = []
                        
                    if get_sinks:
                        console.print(f"  ├─ [cyan]◆ Extracted {len(get_sinks)} new sink patterns[/cyan]")
                        from src.tools.actions import search_pattern

                        for sink in get_sinks:

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
                                    search_sinks = search_pattern({"pattern": pat}, str(scan_dir))

                                    if search_sinks.startswith("[PATTERN"):
                                        lines = search_sinks.split("\n")[1:]

                                        for line in lines:

                                            if line.startswith("  ") and ":" in line:
                                                parts = line.strip().split(":", 2)

                                                if len(parts) >= 2:
                                                    get_file = parts[0]

                                                    try:
                                                        get_num = int(parts[1])

                                                    except ValueError:
                                                        get_num = 1
                                                    
                                                    add_flaw = {
                                                        "id": f"dynamic-sink-{pat}",
                                                        "message": f"Dynamically expanded sink from CVE: {desc}",
                                                        "path": get_file,
                                                        "start_line": get_num,
                                                        "end_line": get_num,
                                                        "severity": sink.get("severity", "WARNING") if isinstance(sink, dict) else "WARNING"
                                                    }
                                                    find_flaws.append(add_flaw)

                                except Exception as e:
                                    pass

                        console.print("  └─ [bold green]✔ Injected![/bold green]")

                    else:
                        console.print("  └─ [dim]No extra sinks![/dim]")

            except Exception as catch_rag:
                console.print(f"  └─ [bold red]✖ RAG failed: {catch_rag}[/bold red]")

    else:
        from cli.views.logger import console
        logger.section("MULTI-AGENT")
        console.print(f"  [bold magenta]● RAG AGENT[/bold magenta]{show_tag}")
        console.print("  └─ [dim]No dependencies found! Skip![/dim]")

    # Build combined CVE context for Auditing Agent (from all CVEs processed)
    get_context = "\n\n---\n\n".join(get_parts) if get_parts else "No relevant supply chain vulnerabilities found in project dependencies."

    # Run Semgrep after Expander so we can combine findings
    get_semgrep = semgrep.scan_code(str(scan_dir), scan_rules)
    find_flaws.extend(get_semgrep)
    
    seen = set()
    deduped = []
    for f in find_flaws:
        key = (f.get("path"), f.get("start_line"), f.get("id"))
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    find_flaws = deduped
    
    get_result["findings"] = find_flaws
    
    semgrep.report_scan(find_flaws)

    if not find_flaws:
        pass

    else:
        logger.console.print()

        for loop_idx, check_item in enumerate(find_flaws):
            logger.console.print(f"  Working [bold]{loop_idx+1}/{len(find_flaws)}[/bold]")
            logger.console.print(f"  └─ [blue]{check_item['path']}[/blue]")
            
            try:
                finding_path = str(scan_dir / check_item["path"]) if check_item["path"] != str(scan_dir) else str(scan_dir)
                get_ast = use_module.extract_context(finding_path, check_item["start_line"], check_item["end_line"], scan_dir=str(scan_dir))

                if build_context:
                    get_ast += f"\n\n[INTER-PROCEDURAL TAINT ANALYSIS]\n{build_context[:1500]}"

            except Exception as ext_err:
                get_ast = f"Error extracting AST context: {ext_err}"

                if build_context:
                    get_ast += f"\n\n[INTER-PROCEDURAL TAINT ANALYSIS]\n{build_context[:1500]}"
            
            check_item["get_ast"] = get_ast

            try:
                import textwrap
                logger.blank()
                
                set_retries = 2
                count_retry = 0
                get_trace = {}
                
                set_scan = MODELS[4]
                logger.console.print(f"  [bold magenta]● SCANNING AGENT[/bold magenta] [[cyan]{set_scan}[/cyan]]")
                
                while count_retry <= set_retries:
                    get_trace = scan_agents.start_scan(
                        check_item, get_ast,
                        use_model=MODELS[4], # Scanning Agent Role
                        scan_dir=str(scan_dir),
                        use_module=use_module,
                    )
                    
                    if get_trace and get_trace.get("data_flow"):
                        check_item["dataflow_trace"] = json.dumps(get_trace["data_flow"], indent=2)
                        count_hops = len(get_trace["data_flow"])

                        if get_trace.get("source_identified"):
                            logger.console.print(f"  ├─ [cyan]◆ Source:[/cyan] [dim]{get_trace.get('source_variable', 'Unknown')}[/dim]")
                            logger.console.print(f"  ├─ [cyan]◆ Sink:[/cyan] [dim]{get_trace.get('sink_function', 'Unknown')}[/dim]")

                            for check_hop in get_trace["data_flow"]:
                                logger.console.print(f"  │  [dim]Hop {check_hop.get('step')}: {check_hop.get('variable')} -> {check_hop.get('operation')}[/dim]")

                        logger.console.print(f"  └─ [bold green]✔ {count_hops} Hops[/bold green]")
                        break
                    
                    elif get_trace and get_trace.get("use_surrogate"):
                        use_surrogate = get_trace.get("surrogate_function", "Unknown")
                        check_item["sink_context"] = f"Original sink was unreachable. We are now treating '{use_surrogate}' as the sink. Use find_callers('{use_surrogate}') if needed."
                        count_retry += 1
                        logger.console.print(f"  ├─ [yellow]⚠ Flow broken → Surrogate: {use_surrogate} (retry {count_retry}/{set_retries})[/yellow]")
                        
                    else:
                        check_item["dataflow_trace"] = "No trace available"
                        logger.console.print(f"  └─ [bold yellow]⚠ Data flow untraceable[/bold yellow]")
                        break
                
                if count_retry > set_retries:
                    check_item["dataflow_trace"] = "No trace available (max retries reached)"
                    logger.console.print(f"  └─ [bold yellow]⚠ Data flow untraceable after {set_retries} retries[/bold yellow]")

            except Exception as catch_scan:
                logger.console.print(f"  └─ [bold red]✖ Data Flow Tracing failed: {catch_scan}[/bold red]")
                check_item["dataflow_trace"] = f"Trace Error: {catch_scan}"

            check_vuln = False

            try:
                import textwrap
                logger.blank()
                set_audit = MODELS[3]
                logger.console.print(f"  [bold magenta]● AUDITING AGENT[/bold magenta] [[cyan]{set_audit}[/cyan]]")

                get_verdict = audit_agents.start_audit(
                    check_item, get_ast, get_context,
                    use_model=MODELS[3], # Auditing Agent Role
                    scan_dir=str(scan_dir),
                    use_module=use_module,
                )

                is_vuln = get_verdict.get("verdict", "").upper() == "VULNERABLE"
                audit_reasoning = get_verdict.get("reasoning", "")

                if audit_reasoning:
                    set_width = max(60, logger.console.width - 10)

                    for get_line in textwrap.wrap(audit_reasoning, width=set_width):
                        logger.console.print(f"  │  [dim]{get_line}[/dim]")

                if is_vuln:
                    logger.console.print(
                        f"  ├─ [bold red]✖ VULNERABLE[/bold red]"
                    )
                    logger.console.print(
                        f"  ├─ [dim][CVSS: {get_verdict.get('cvss_estimate', 'N/A')}] [{get_verdict.get('severity', 'UNKNOWN')}][/dim]"
                    )
                    logger.console.print(
                        f"  ├─ [dim][Confidence: {get_verdict.get('confidence', 'N/A')}%][/dim]"
                    )
                    logger.console.print(
                        f"  └─ [dim][Class: {get_verdict.get('vuln_class', 'N/A')}][/dim]"
                    )
                    get_result["is_vulnerable"] = True
                    check_vuln = True
                    check_item.update(get_verdict)

                else:
                    logger.console.print(
                        f"  └─ [bold green]✓ SAFE[/bold green] "
                        f"[dim][Confidence: {get_verdict.get('confidence', 'N/A')}%][/dim]"
                    )

            except Exception as catch_audit:
                logger.console.print(f"  ├─ [bold red]✖ Auditor Agent failed: {catch_audit}[/bold red]")



                if do_fix:

                    try:
                        logger.blank()
                        set_fix = MODELS[0]
                        logger.console.print(f"  [bold magenta]● FIXING AGENT[/bold magenta] [[cyan]{set_fix}[/cyan]]")
                        from src.fix.agents import models as use_fix
                        get_fix = use_fix.start_fix(
                            check_item, get_ast, get_context,
                            use_model=set_model,
                            scan_dir=str(scan_dir),
                            use_module=use_module,
                        )
                        check_item["fix"] = get_fix

                        if get_fix and "patches" in get_fix:

                            if "explanation" in get_fix:
                                set_width = max(60, logger.console.width - 10)

                                for get_line in textwrap.wrap(get_fix['explanation'], width=set_width):
                                    logger.console.print(f"  │  [dim]{get_line}[/dim]")

                            for p_idx, patch_item in enumerate(get_fix["patches"]):
                                logger.console.print(f"  │  [dim]Patch {p_idx+1}: {patch_item.get('get_file')}[/dim]")

                            logger.console.print(f"  └─ [bold green]✔ Generated {len(get_fix['patches'])} patch(es)[/bold green]")

                        else:
                            logger.console.print(f"  └─ [bold yellow]⚠ Failed to generate fix[/bold yellow]")

                    except Exception as catch_fix:
                        logger.console.print(f"  └─ [bold red]✖ Fixer Agent failed: {catch_fix}[/bold red]")

            logger.blank()

    if make_dir:

        def remove_readonly(func_obj, get_file, exc_info):
            os.chmod(get_file, stat.S_IWRITE)
            func_obj(get_file)
        shutil.rmtree(make_dir, onerror=remove_readonly)

    from rich.table import Table
    from rich.panel import Panel

    logger.blank()
    summary_table = Table(show_header=False, box=None, padding=(0, 2))
    
    count_langs = len(get_result.get("languages", {}))
    count_files = sum(get_result.get("languages", {}).values())
    count_deps = len(get_result.get("dependencies", []))
    elapsed_time = logger.get_time_elapsed_secs()
    count_findings = len(find_flaws)
    count_errors = len([f for f in find_flaws if f.get("severity") == "ERROR"])
    count_warns = len([f for f in find_flaws if f.get("severity") == "WARNING"])
    count_info = len([f for f in find_flaws if f.get("severity") == "INFO"])
    
    is_vulnerable = get_result.get("is_vulnerable", False) or count_errors > 0
    status_msg = "[bold red]✖ VULNERABLE[/bold red]" if is_vulnerable else "[bold green]✓ SAFE[/bold green]"

    summary_table.add_row("Target", f"[bold]{scan_dir.name}[/bold]")
    summary_table.add_row("Languages", f"[cyan]{count_langs}[/cyan]", "Files", f"[cyan]{count_files}[/cyan]")
    summary_table.add_row("Dependencies", f"[cyan]{count_deps}[/cyan]", "Duration", f"{elapsed_time}s")
    summary_table.add_row("", "")
    summary_table.add_row("Findings", f"[bold]{count_findings}[/bold]")

    if count_errors > 0:
        summary_table.add_row("[red]✖ ERROR[/red]", str(count_errors))

    if count_warns > 0:
        summary_table.add_row("[yellow]⚠ WARNING[/yellow]", str(count_warns))

    if count_info > 0:
        summary_table.add_row("[green]✓ INFO[/green]", str(count_info))
    summary_table.add_row("", "")
    summary_table.add_row("Status", status_msg)

    show_panel = Panel(summary_table, title="[bold]SCAN SUMMARY[/bold]", expand=False, border_style="dim")
    logger.console.print(show_panel)
    logger.blank()

    def check_cvss(get_val):
        try:

            return float(get_val.get("cvss_estimate", 0))

        except (TypeError, ValueError):

            return 0.0

    find_flaws.sort(key=check_cvss, reverse=True)
    get_result["findings"] = find_flaws

    return {"status": "success", "data": get_result}


def start_app():
    arg_parser = argparse.ArgumentParser(description="Sinful AI-Based SAST")
    arg_parser.add_argument("target", nargs="?", help="Target directory OR Git URL to scan")
    cli_args = arg_parser.parse_args()

    if not cli_args.target:
        from cli.main import start_cli
        start_cli()
        return

    get_result = run_scan(cli_args.target, None, None)

    if get_result["status"] == "error":
        print(get_result["message"])
        sys.exit(1)


if __name__ == "__main__":
    start_app()
