import argparse
import sys
import shutil
import tempfile
import subprocess
import os
import stat
import json
from pathlib import Path
import importlib.util
import time

from dotenv import load_dotenv
load_dotenv()

from cli.views import logger

MODELS = [
    "deepseek/deepseek-v4-flash",
    "mistralai/codestral-2508",
    "qwen/qwen3.8-max",
    "xiaomi/mimo-v2.5-pro",
    "mistralai/mistral-large-2512"
]

def load_ts_module():
    ts_path = Path("src/audit/tree-sitter.py").resolve()
    spec_loader = importlib.util.spec_from_file_location("tree_sitter", ts_path)
    ts_module = importlib.util.module_from_spec(spec_loader)
    spec_loader.loader.exec_module(ts_module)
    return ts_module

def start_sast(target_path, rule_list=None, model_name=None, auto_fix=False):
    actual_model = model_name or os.environ.get("MODELS", "deepseek/deepseek-v4-flash")
    model_tag = fr" [[cyan]{actual_model}[/cyan]]"
    
    temp_dir = None
    scan_result = {
        "status": "processing",
        "languages": {},
        "language_versions": {},
        "dependencies": [],
        "findings": [],
        "cves": [],
        "nvd_data": [],
        "rag_summary": {},
    }

    if target_path.startswith("http://") or target_path.startswith("https://") or target_path.startswith("git@"):
        print(f"\n[*] Cloning repository: {target_path}")
        temp_dir = tempfile.mkdtemp(prefix="ai_scan_")
        
        try:
            subprocess.run(["git", "clone", "--depth", "1", target_path, temp_dir], check=True, capture_output=True)
            target_dir = Path(temp_dir).resolve()
            
        except subprocess.CalledProcessError as clone_err:
            error_msg = f"Git clone failed: {clone_err.stderr.decode('utf-8') if clone_err.stderr else str(clone_err)}"
            shutil.rmtree(temp_dir, ignore_errors=True)
            return {"status": "error", "message": error_msg}
            
    else:
        target_dir = Path(target_path).resolve()
        if not target_dir.exists():
            return {"status": "error", "message": f"Target directory does not exist: {target_dir}"}

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

        ts_module = load_ts_module()
        
    except Exception as load_err:
        return {"status": "error", "message": f"Failed to load modules: {load_err}"}

    lang_counts = detector.detect_langs(str(target_dir))
    lang_versions = detector.get_lang_versions(lang_counts)
    scan_result["languages"] = lang_counts
    scan_result["language_versions"] = lang_versions
    detector.report_langs(lang_counts, lang_versions)

    parsed_deps = dep_parser.parse_all_deps(str(target_dir))
    scan_result["dependencies"] = parsed_deps
    dep_parser.report_deps(parsed_deps)

    scan_findings = semgrep.scan_code(str(target_dir), rule_list)
    scan_result["findings"] = scan_findings
    semgrep.report_scan(scan_findings)

    try:
        cross_context = ts_module.build_context(str(target_dir))
        if cross_context:
            scan_result["cross_file_context"] = cross_context
        else:
            cross_context = ""
    except Exception:
        cross_context = ""

    if not scan_findings and not cross_context:
        return {"status": "success", "message": "No vulnerabilities found.", "data": scan_result}

    if not scan_findings and cross_context:
        scan_findings = [{
            "id": "sinful-cross-file-taint",
            "path": str(target_dir),
            "start_line": 1,
            "end_line": 1,
            "severity": "WARNING",
            "message": "Cross-file taint path detected by inter-procedural analysis.",
            "lines": "",
            "cwe": [],
            "dataflow_trace": cross_context,
        }]
        scan_result["findings"] = scan_findings

    if parsed_deps:
        logger.section("SUPPLY CHAIN")
        try:
            cve_list = osv.check_osv_vulns(parsed_deps)
        except AttributeError:
            cve_list = []

        from src.rag import usage
        cve_list = usage.check_code_usage(str(target_dir), cve_list, ts_module)
        cve_list = [cve_item for cve_item in cve_list if cve_item.get("reachable", True)]

        scan_result["cves"] = cve_list
        osv.report_osv(cve_list)

        cve_ids = set()
        for cve_item in cve_list:
            for alias_id in cve_item.get("cve", []):
                if str(alias_id).startswith("CVE-"):
                    cve_ids.add(alias_id)

        if cve_ids:
            from concurrent.futures import ThreadPoolExecutor, as_completed
            from cli.views.logger import console as cve_console
            import threading

            nvd_semaphore = threading.Semaphore(5)

            def get_cve_info(cve_id: str):
                with nvd_semaphore:
                    nvd_data = nvd.fetch_nvd_cve(cve_id)
                if not nvd_data:
                    return None

                ref_links = nvd_data.get("references", [])
                if ref_links:
                    nvd_data["firecrawl_poc"] = ""
                    for ref_url in ref_links[:2]:
                        scraped_md = firecrawl.scrape_firecrawl_url(ref_url)
                        if scraped_md:
                            nvd_data["firecrawl_poc"] += f"\n\nSource: {ref_url}\n{scraped_md}"

                github_data = github.search_github_issues(cve_id)
                if "error" not in github_data:
                    nvd_data["github_issues"] = github_data.get("github_issues", [])

                return nvd_data

            cve_id_list = list(cve_ids)

            with ThreadPoolExecutor(max_workers=5) as pool:
                future_map = {}
                for list_idx, cid in enumerate(cve_id_list):
                    future_map[pool.submit(get_cve_info, cid)] = cid
                    if list_idx < len(cve_id_list) - 1:
                        time.sleep(0.5)

                for future in as_completed(future_map):
                    cve_id = future_map[future]
                    try:
                        nvd_result = future.result()
                        if nvd_result:
                            cve_console.print(f"  [dim]✔ Fetched[/dim] [bold green]{cve_id}[/bold green]")
                            nvd.report_nvd(nvd_result)
                            scan_result["nvd_data"].append(nvd_result)
                    except Exception as fut_err:
                        cve_console.print(f"  [dim]Failed to fetch {cve_id}: {fut_err}[/dim]")

    cve_context = "No relevant supply chain vulnerabilities found in project dependencies."
    
    if scan_result["cves"] or scan_result["nvd_data"] or scan_result.get("language_versions"):
        cve_data_str = json.dumps({
            "osv": scan_result["cves"], 
            "nvd": scan_result["nvd_data"],
            "runtimes": scan_result.get("language_versions")
        }, indent=2)
        from cli.views.logger import console
        logger.section("MULTI-AGENT")
        console.print(f"  [bold magenta]● RAG AGENT[/bold magenta]{model_tag}")
        import textwrap
        try:
            rag_summary = rag_agents.start_rag(cve_data_str, model_name=actual_model)
            scan_result["rag_summary"] = rag_summary
            cve_context = json.dumps(rag_summary, indent=2)
            if "cve_id" in rag_summary and rag_summary["cve_id"] != "None":
                console.print(f"  ├─ [cyan]◆ Analyzing {rag_summary['cve_id']} {rag_summary.get('dependency', 'Unknown')}[/cyan]")
            if "attack_vector" in rag_summary:
                wrap_width = max(60, console.width - 15)
                for w_line in textwrap.wrap(rag_summary['attack_vector'], width=wrap_width, initial_indent="Vector: ", subsequent_indent="        "):
                    console.print(f"  │  [dim]{w_line}[/dim]")
            if "mitigation" in rag_summary:
                wrap_width = max(60, console.width - 15)
                for w_line in textwrap.wrap(rag_summary['mitigation'], width=wrap_width, initial_indent="Mitigation: ", subsequent_indent="            "):
                    console.print(f"  │  [dim]{w_line}[/dim]")
            console.print("  └─ [bold green]✔ RAG completed![/bold green]")
        except Exception as rag_err:
            console.print(f"  └─ [bold red]✖ RAG failed: {rag_err}[/bold red]")
            scan_result["rag_summary"] = {"error": str(rag_err)}
            cve_context = cve_data_str
    else:
        from cli.views.logger import console
        logger.section("MULTI-AGENT")
        console.print(f"  [bold magenta]● RAG AGENT[/bold magenta]{model_tag}")
        console.print("  └─ [dim]No dependencies found! Skip![/dim]")

    if not scan_findings:
        pass
    else:
        logger.console.print()

        for loop_idx, finding_item in enumerate(scan_findings):
            logger.console.print(f"  Working [bold]{loop_idx+1}/{len(scan_findings)}[/bold]")
            logger.console.print(f"  └─ [blue]{finding_item['path']}[/blue]")
            
            try:
                finding_path = str(target_dir / finding_item["path"]) if finding_item["path"] != str(target_dir) else str(target_dir)
                ast_context = ts_module.extract_context(finding_path, finding_item["start_line"], finding_item["end_line"], target_dir=str(target_dir))
                if cross_context:
                    ast_context += f"\n\n[INTER-PROCEDURAL TAINT ANALYSIS]\n{cross_context[:1500]}"
            except Exception as ext_err:
                ast_context = f"Error extracting AST context: {ext_err}"
                if cross_context:
                    ast_context += f"\n\n[INTER-PROCEDURAL TAINT ANALYSIS]\n{cross_context[:1500]}"
            
            finding_item["ast_context"] = ast_context

            try:
                import textwrap
                logger.blank()
                logger.console.print(f"  [bold magenta]● SCANNING AGENT[/bold magenta]{model_tag}")
                trace_json = scan_agents.start_scan(
                    finding_item, ast_context,
                    model_name=actual_model,
                    target_dir=str(target_dir),
                    ts_module=ts_module,
                )
                if trace_json and "data_flow" in trace_json:
                    finding_item["dataflow_trace"] = json.dumps(trace_json["data_flow"], indent=2)
                    hops_count = len(trace_json["data_flow"])

                    if trace_json.get("source_identified"):
                        logger.console.print(f"  ├─ [cyan]◆ Source:[/cyan] [dim]{trace_json.get('source_variable', 'Unknown')}[/dim]")
                        logger.console.print(f"  ├─ [cyan]◆ Sink:[/cyan] [dim]{trace_json.get('sink_function', 'Unknown')}[/dim]")

                        for hop_item in trace_json["data_flow"]:
                            logger.console.print(f"  │  [dim]Hop {hop_item.get('step')}: {hop_item.get('variable')} -> {hop_item.get('operation')}[/dim]")

                    logger.console.print(f"  └─ [bold green]✔ {hops_count} Hops[/bold green]")
                else:
                    finding_item["dataflow_trace"] = "No trace available"
                    logger.console.print(f"  └─ [bold yellow]⚠ Data flow untraceable.[/bold yellow]")
            except Exception as scan_err:
                logger.console.print(f"  └─ [bold red]✖ Data Flow Tracing failed: {scan_err}[/bold red]")
                finding_item["dataflow_trace"] = f"Trace Error: {scan_err}"

            is_vuln_flag = False
            try:
                import textwrap
                logger.blank()
                logger.console.print(f"  [bold magenta]● AUDITING AGENT[/bold magenta]{model_tag}")

                verdict_data = audit_agents.start_audit(
                    finding_item, ast_context, cve_context,
                    model_name=actual_model,
                    target_dir=str(target_dir),
                    ts_module=ts_module,
                )

                is_vuln = verdict_data.get("verdict", "").upper() == "VULNERABLE"
                audit_reasoning = verdict_data.get("reasoning", "")

                if audit_reasoning:
                    wrap_width = max(60, logger.console.width - 10)
                    for w_line in textwrap.wrap(audit_reasoning, width=wrap_width):
                        logger.console.print(f"  │  [dim]{w_line}[/dim]")

                if is_vuln:
                    logger.console.print(
                        f"  ├─ [bold red]✖ VULNERABLE[/bold red] "
                        f"[dim][CVSS: {verdict_data.get('cvss_estimate', 'N/A')} "
                        f"- {verdict_data.get('severity', 'UNKNOWN')}][/dim]"
                    )
                    logger.console.print(
                        f"  └─ [dim]Confidence: {verdict_data.get('confidence', 'N/A')}% "
                        f"| Class: {verdict_data.get('vuln_class', 'N/A')}[/dim]"
                    )
                    scan_result["is_vulnerable"] = True
                    is_vuln_flag = True
                    finding_item.update(verdict_data)
                else:
                    logger.console.print(
                        f"  └─ [bold green]✓ SAFE[/bold green] "
                        f"[dim][Confidence: {verdict_data.get('confidence', 'N/A')}%][/dim]"
                    )

            except Exception as audit_err:
                logger.console.print(f"  ├─ [bold red]✖ Auditor Agent failed: {audit_err}[/bold red]")

            if is_vuln_flag:
                try:
                    logger.blank()
                    logger.console.print(f"  [bold magenta]● HACKING AGENT[/bold magenta]{model_tag}")
                    from src.hack.agents import models as hack_agents
                    poc_json = hack_agents.start_hack(
                        finding_item, ast_context, cve_context,
                        model_name=actual_model,
                        target_dir=str(target_dir),
                        ts_module=ts_module,
                    )
                    finding_item["poc"] = poc_json
                    if poc_json and "poc_type" in poc_json:
                        logger.console.print(f"  ├─ [cyan]◆ Type:[/cyan] [dim]{poc_json['poc_type']}[/dim]")
                        if "description" in poc_json:
                            wrap_width = max(60, logger.console.width - 10)
                            for w_line in textwrap.wrap(poc_json['description'], width=wrap_width):
                                logger.console.print(f"  │  [dim]{w_line}[/dim]")
                        if "payload" in poc_json:
                            logger.console.print(f"  │  [bold red]Payload:[/bold red]")
                            for p_line in poc_json['payload'].split('\n'):
                                logger.console.print(f"  │    [dim]{p_line}[/dim]")
                        logger.console.print(f"  └─ [bold green]✔ PoC: {poc_json['poc_type']}[/bold green]")
                    else:
                        logger.console.print(f"  └─ [bold yellow]⚠ Failed to generate PoC[/bold yellow]")
                except Exception as hack_err:
                    logger.console.print(f"  └─ [bold red]✖ Hacker Agent failed: {hack_err}[/bold red]")

                if auto_fix:
                    try:
                        logger.blank()
                        logger.console.print(f"  [bold magenta]● FIXING AGENT[/bold magenta]{model_tag}")
                        from src.fix.agents import models as fix_agents
                        fix_json = fix_agents.start_fix(
                            finding_item, ast_context, cve_context,
                            model_name=actual_model,
                            target_dir=str(target_dir),
                            ts_module=ts_module,
                        )
                        finding_item["fix"] = fix_json
                        if fix_json and "patches" in fix_json:
                            if "explanation" in fix_json:
                                wrap_width = max(60, logger.console.width - 10)
                                for w_line in textwrap.wrap(fix_json['explanation'], width=wrap_width):
                                    logger.console.print(f"  │  [dim]{w_line}[/dim]")

                            for p_idx, patch_item in enumerate(fix_json["patches"]):
                                logger.console.print(f"  │  [dim]Patch {p_idx+1}: {patch_item.get('file_path')}[/dim]")

                            logger.console.print(f"  └─ [bold green]✔ Generated {len(fix_json['patches'])} patch(es)[/bold green]")
                        else:
                            logger.console.print(f"  └─ [bold yellow]⚠ Failed to generate fix[/bold yellow]")
                    except Exception as fix_err:
                        logger.console.print(f"  └─ [bold red]✖ Fixer Agent failed: {fix_err}[/bold red]")

            logger.blank()

    if temp_dir:
        def remove_readonly(func_obj, file_path, exc_info):
            os.chmod(file_path, stat.S_IWRITE)
            func_obj(file_path)
        shutil.rmtree(temp_dir, onerror=remove_readonly)

    from rich.table import Table
    from rich.panel import Panel

    logger.blank()
    summary_table = Table(show_header=False, box=None, padding=(0, 2))
    
    count_langs = len(scan_result.get("languages", {}))
    count_files = sum(scan_result.get("languages", {}).values())
    count_deps = len(scan_result.get("dependencies", []))
    elapsed_time = logger.get_time_elapsed_secs()
    count_findings = len(scan_findings)
    count_errors = len([f for f in scan_findings if f.get("severity") == "ERROR"])
    count_warns = len([f for f in scan_findings if f.get("severity") == "WARNING"])
    count_info = len([f for f in scan_findings if f.get("severity") == "INFO"])
    
    is_vulnerable = scan_result.get("is_vulnerable", False) or count_errors > 0
    status_msg = "[bold red]✖ VULNERABLE[/bold red]" if is_vulnerable else "[bold green]✓ SAFE[/bold green]"

    summary_table.add_row("Target", f"[bold]{target_dir.name}[/bold]")
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

    summary_panel = Panel(summary_table, title="[bold]SCAN SUMMARY[/bold]", expand=False, border_style="dim")
    logger.console.print(summary_panel)
    logger.blank()

    scan_findings.sort(key=lambda item_val: float(item_val.get("cvss_estimate", 0)), reverse=True)
    scan_result["findings"] = scan_findings

    return {"status": "success", "data": scan_result}


def start_app():
    arg_parser = argparse.ArgumentParser(description="Sinful AI-Based SAST")
    arg_parser.add_argument("target", nargs="?", help="Target directory OR Git URL to scan")
    cli_args = arg_parser.parse_args()

    if not cli_args.target:
        from cli.main import start_cli
        start_cli()
        return

    scan_result = start_sast(cli_args.target, None, None)

    if scan_result["status"] == "error":
        print(scan_result["message"])
        sys.exit(1)


if __name__ == "__main__":
    start_app()
