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
    "deepseek/deepseek-v4-flash",      # DeepSeek V4 Flash 
    "mistralai/codestral-2508",        # Codestral
    "qwen/qwen3.8-max",                # Alibaba Qwen
    "xiaomi/mimo-v2.5-pro",            # Xiaomi MiMo 
    "mistralai/mistral-large-2512"     # Mistral Large
]

def load_tree_sitter():
    # Load tree sitter module dynamically
    ts_path = Path("src/audit/tree-sitter.py").resolve()
    spec_loader = importlib.util.spec_from_file_location("tree_sitter", ts_path)
    ts_module = importlib.util.module_from_spec(spec_loader)
    spec_loader.loader.exec_module(ts_module)
    return ts_module

def run_sast(target_path, rule_list=None, model=None, fix=False):
    import os
    actual_model = model or os.environ.get("MODELS", "deepseek/deepseek-v4-flash")
    model_tag = fr" [[cyan]{actual_model}[/cyan]]"
    
    # Initialize scan result structure
    temp_dir = None
    scan_result = {
        "status": "processing",
        "languages": {},
        "dependencies": [],
        "findings": [],
        "cves": [],
        "nvd_data": [],
        "ai_reviews": [],
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
        from src.audit.agents import models as agents

        ts_module = load_tree_sitter()
        
    except Exception as load_err:
        return {"status": "error", "message": f"Failed to load modules: {load_err}"}

    language_counts = detector.detect(str(target_dir))
    language_versions = detector.get_versions(language_counts)
    scan_result["languages"] = language_counts
    scan_result["language_versions"] = language_versions
    detector.report(language_counts, language_versions)

    parsed_deps = dep_parser.parse(str(target_dir))
    scan_result["dependencies"] = parsed_deps
    dep_parser.report(parsed_deps)

    scan_findings = semgrep.scan(str(target_dir), rule_list)
    scan_result["findings"] = scan_findings
    semgrep.report(scan_findings)

    try:
        cross_file_context = ts_module.build_context(str(target_dir))
        if cross_file_context:
            scan_result["cross_file_context"] = cross_file_context
        else:
            cross_file_context = ""
    except Exception:
        cross_file_context = ""

    if not scan_findings and not cross_file_context:
        return {"status": "success", "message": "No vulnerabilities found.", "data": scan_result}

    if not scan_findings and cross_file_context:
        scan_findings = [{
            "id": "sinful-cross-file-taint",
            "path": str(target_dir),
            "start_line": 1,
            "end_line": 1,
            "severity": "WARNING",
            "message": "Cross-file taint path detected by inter-procedural analysis.",
            "lines": "",
            "cwe": [],
            "dataflow_trace": cross_file_context,
        }]
        scan_result["findings"] = scan_findings

    if parsed_deps:
        try:
            cve_list = osv.check(parsed_deps)
        except AttributeError:
            cve_list = osv.fetch(parsed_deps)

        from src.rag import usage
        cve_list = usage.check(str(target_dir), cve_list, ts_module)
        cve_list = [c for c in cve_list if c.get("reachable", True)]

        scan_result["cves"] = cve_list
        osv.report(cve_list)

        cve_ids = set()
        for cve_item in cve_list:
            for alias_id in cve_item.get("cve", []):
                if str(alias_id).startswith("CVE-"):
                    cve_ids.add(alias_id)

        if cve_ids:
            for loop_idx, cve_id in enumerate(list(cve_ids)):
                nvd_data = nvd.fetch(cve_id)
                
                if nvd_data:
                    nvd.report(nvd_data)
                    ref_links = nvd_data.get("references", [])
                    
                    if ref_links:
                        nvd_data["firecrawl_poc"] = ""
                        for ref_url in ref_links[:2]:
                            display_ref = ref_url if len(ref_url) <= 60 else ref_url[:57] + "..."
                            from cli.views.logger import console
                            console.print(
                                f"  [dim]Scraping PoC via[/dim] "
                                f"[bold green]Firecrawl[/bold green]: "
                                f"[dim][link={ref_url}]{display_ref}[/link][/dim]"
                            )
                            scraped_md = firecrawl.scrape(ref_url)
                            
                            if scraped_md:
                                nvd_data["firecrawl_poc"] += f"\n\nSource: {ref_url}\n{scraped_md}"
                            
                            time.sleep(15)
                            
                    from cli.views.logger import console
                    console.print(f"  [dim]Searching GitHub for[/dim] [bold green]{cve_id}[/bold green]...")
                    github_data = github.search(cve_id)
                    if "error" not in github_data:
                        github.report(github_data)
                        nvd_data["github_issues"] = github_data.get("github_issues", [])
                    else:
                        console.print(f"  [dim]GitHub search error: {github_data['error']}[/dim]")
                                
                    scan_result["nvd_data"].append(nvd_data)
                
                if loop_idx < len(cve_ids) - 1:
                    time.sleep(6)

    cve_context = "No relevant supply chain vulnerabilities found in project dependencies."
    
    if scan_result["cves"] or scan_result["nvd_data"] or scan_result.get("language_versions"):
        cve_data_str = json.dumps({
            "osv": scan_result["cves"], 
            "nvd": scan_result["nvd_data"],
            "runtimes": scan_result.get("language_versions")
        }, indent=2)
        from cli.views.logger import console
        console.print(f"  [bold magenta]● RAG AGENT[/bold magenta]{model_tag}")
        import textwrap
        try:
            rag_summary = rag_agents.fetch(cve_data_str, model=model)
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
            console.print("  └─ [bold green]✔ RAG Summary generated[/bold green]")
        except Exception as e:
            console.print(f"  └─ [bold red]✖ RAG Agent failed: {e}[/bold red]")
            cve_context = cve_data_str
    else:
        from cli.views.logger import console
        console.print(f"  [bold magenta]● RAG AGENT[/bold magenta]{model_tag}")
        console.print("  └─ [dim]No dependencies found! Skip![/dim]")

    critical_findings = scan_findings
    
    if not critical_findings:
        pass
    else:
        logger.section("MULTI-AGENT")

        for loop_idx, finding_item in enumerate(critical_findings):
            logger.console.print(f"  Working [bold]{loop_idx+1}/{len(critical_findings)}[/bold]")
            logger.console.print(f"  └─ [blue]{finding_item['path']}[/blue]")
            
            try:
                finding_path = str(target_dir / finding_item["path"]) if finding_item["path"] != str(target_dir) else str(target_dir)
                ast_context = ts_module.extract_context(finding_path, finding_item["start_line"], finding_item["end_line"], target_dir=str(target_dir))
                # Append cross-file context if available
                if cross_file_context:
                    ast_context += f"\n\n[INTER-PROCEDURAL TAINT ANALYSIS]\n{cross_file_context[:1500]}"
            except Exception as ext_err:
                ast_context = f"Error extracting AST context: {ext_err}"
                if cross_file_context:
                    ast_context += f"\n\n[INTER-PROCEDURAL TAINT ANALYSIS]\n{cross_file_context[:1500]}"

            try:
                import textwrap
                logger.blank()
                logger.console.print(f"  [bold magenta]● SCANNING AGENT[/bold magenta]{model_tag}")
                trace_json = scan_agents.fetch(finding_item, ast_context, model=model)
                if trace_json and "data_flow" in trace_json:
                    finding_item["dataflow_trace"] = json.dumps(trace_json["data_flow"], indent=2)
                    hops_count = len(trace_json["data_flow"])
                    
                    if trace_json.get("source_identified"):
                        logger.console.print(f"  ├─ [cyan]◆ Source:[/cyan] [dim]{trace_json.get('source_variable', 'Unknown')}[/dim]")
                        logger.console.print(f"  ├─ [cyan]◆ Sink:[/cyan] [dim]{trace_json.get('sink_function', 'Unknown')}[/dim]")
                        
                        for hop in trace_json["data_flow"]:
                            logger.console.print(f"  │  [dim]Hop {hop.get('step')}: {hop.get('variable')} -> {hop.get('operation')}[/dim]")
                            
                    logger.console.print(f"  └─ [bold green]✔ {hops_count} Hops[/bold green]")
                else:
                    finding_item["dataflow_trace"] = "No trace available"
                    logger.console.print(f"  └─ [bold yellow]⚠ Data flow untraceable.[/bold yellow]")
            except Exception as e:
                logger.console.print(f"  └─ [bold red]✖ Data Flow Tracing failed: {e}[/bold red]")
                finding_item["dataflow_trace"] = f"Trace Error: {e}"

            is_vuln_flag = False
            ai_review = ""
            try:
                logger.blank()
                logger.console.print(f"  [bold magenta]● AUDITING AGENT[/bold magenta]{model_tag}")
                fetch_result = agents.fetch(finding_item, ast_context, cve_context, model=model)
                ai_review = fetch_result if not isinstance(fetch_result, tuple) else fetch_result[0]
                
                import re
                json_match = re.search(r'```json\s*(\{.*?\})\s*```', ai_review, re.DOTALL)
                verdict_data = {}
                if json_match:
                    try:
                        verdict_data = json.loads(json_match.group(1))
                        ai_review = ai_review.replace(json_match.group(0), "")
                    except Exception:
                        pass

                is_first_line = True
                for text_line in ai_review.split("\n"):
                    text_line = text_line.strip()
                    if not text_line: continue
                    clean_lower = text_line.lower().replace("*", "").replace("#", "").strip()
                    
                    if clean_lower.startswith("step ") or clean_lower.startswith("final result") or "final result" in clean_lower:
                        verdict_title = text_line.replace("*", "").replace("###", "").strip()
                        logger.console.print(f"  ├─ [cyan]◆ {verdict_title}[/cyan]")
                        is_first_line = True
                    elif text_line.startswith("[VULNERABLE]") or "VULNERABLE" in text_line:
                        pass
                    elif text_line.startswith("[SAFE]") or "SAFE" in text_line:
                        pass
                    else:
                        if text_line.startswith("* ") or text_line.startswith("- "): text_line = text_line[2:]
                        if text_line.endswith(".") and len(text_line) < 80:
                            text_line = text_line[:-1]
                        
                        wrap_width = max(60, logger.console.width - 10)
                        for w_line in textwrap.wrap(text_line, width=wrap_width):
                            logger.console.print(f"  │  [dim]{w_line}[/dim]")

                if verdict_data:
                    is_vuln = verdict_data.get("verdict", "").upper() == "VULNERABLE"
                    if is_vuln:
                        logger.console.print(f"  ├─ [bold red]✖ VULNERABLE[/bold red] [dim][CVSS: {verdict_data.get('cvss_estimate', 'N/A')} - {verdict_data.get('severity', 'UNKNOWN')}][/dim]")
                        logger.console.print(f"  └─ [dim]Confidence: {verdict_data.get('confidence', 'N/A')}/10 | Class: {verdict_data.get('vuln_class', 'N/A')}[/dim]")
                        scan_result["is_vulnerable"] = True
                        is_vuln_flag = True
                        finding_item.update(verdict_data)
                    else:
                        logger.console.print(f"  └─ [bold green]✓ SAFE[/bold green] [dim][Confidence: {verdict_data.get('confidence', 'N/A')}/10][/dim]")
                else:
                    if "VULNERABLE" in ai_review:
                        logger.console.print("  └─ [bold red]✖ VULNERABLE[/bold red]")
                        scan_result["is_vulnerable"] = True
                        is_vuln_flag = True
                    else:
                        logger.console.print("  └─ [bold green]✓ SAFE[/bold green]")

            except Exception as e:
                logger.console.print(f"  ├─ [bold red]✖ Auditor Agent failed: {e}[/bold red]")
                ai_review = f"Error: {e}"

            if is_vuln_flag:
                try:
                    logger.blank()
                    logger.console.print(f"  [bold magenta]● HACKING AGENT[/bold magenta]{model_tag}")
                    from src.hack.agents import models as hack_agents
                    poc_json = hack_agents.gen_poc(finding_item, ast_context, cve_context, model=model)
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
                except Exception as e:
                    logger.console.print(f"  └─ [bold red]✖ Hacker Agent failed: {e}[/bold red]")
                    
                if fix:
                    try:
                        logger.blank()
                        logger.console.print(f"  [bold magenta]● FIXING AGENT[/bold magenta]{model_tag}")
                        from src.fix.agents import models as fix_agents
                        fix_json = fix_agents.gen_fix(finding_item, ast_context, cve_context, model=model)
                        finding_item["fix"] = fix_json
                        if fix_json and "patches" in fix_json:
                            if "explanation" in fix_json:
                                wrap_width = max(60, logger.console.width - 10)
                                for w_line in textwrap.wrap(fix_json['explanation'], width=wrap_width):
                                    logger.console.print(f"  │  [dim]{w_line}[/dim]")
                            
                            for p_idx, patch in enumerate(fix_json["patches"]):
                                logger.console.print(f"  │  [dim]Patch {p_idx+1}: {patch.get('file_path')} Lines {patch.get('start_line')}-{patch.get('end_line')}[/dim]")
                            
                            logger.console.print(f"  └─ [bold green]✔ Generated {len(fix_json['patches'])} patch(es)[/bold green]")
                        else:
                            logger.console.print(f"  └─ [bold yellow]⚠ Failed to generate fix[/bold yellow]")
                    except Exception as e:
                        logger.console.print(f"  └─ [bold red]✖ Fixer Agent failed: {e}[/bold red]")

            logger.blank()
            scan_result["ai_reviews"].append({"finding": finding_item, "review": ai_review})

            if loop_idx < len(critical_findings) - 1:
                time.sleep(5)

    if temp_dir:
        def remove_readonly(func, path, excinfo):
            os.chmod(path, stat.S_IWRITE)
            func(path)
        shutil.rmtree(temp_dir, onerror=remove_readonly)

    from rich.table import Table
    from rich.panel import Panel

    logger.blank()
    summary_table = Table(show_header=False, box=None, padding=(0, 2))
    
    count_langs = len(scan_result.get("languages", {}))
    count_files = sum(scan_result.get("languages", {}).values())
    count_deps = len(scan_result.get("dependencies", []))
    elapsed_duration = logger.get_time_elapsed_secs()
    count_findings = len(scan_findings)
    count_errors = len([find_item for find_item in scan_findings if find_item["severity"] == "ERROR"])
    count_warnings = len([find_item for find_item in scan_findings if find_item["severity"] == "WARNING"])
    count_info = len([find_item for find_item in scan_findings if find_item["severity"] == "INFO"])
    
    is_vulnerable = scan_result.get("is_vulnerable", False) or count_errors > 0
    status_str = "[bold red]✖ VULNERABLE[/bold red]" if is_vulnerable else "[bold green]✓ SAFE[/bold green]"

    summary_table.add_row("Target", f"[bold]{target_dir.name}[/bold]")
    summary_table.add_row("Languages", f"[cyan]{count_langs}[/cyan]", "Files", f"[cyan]{count_files}[/cyan]")
    summary_table.add_row("Dependencies", f"[cyan]{count_deps}[/cyan]", "Duration", f"{elapsed_duration}s")
    summary_table.add_row("", "")
    summary_table.add_row("Findings", f"[bold]{count_findings}[/bold]")
    if count_errors > 0:
        summary_table.add_row("[red]✖ ERROR[/red]", str(count_errors))
    if count_warnings > 0:
        summary_table.add_row("[yellow]⚠ WARNING[/yellow]", str(count_warnings))
    if count_info > 0:
        summary_table.add_row("[green]✓ INFO[/green]", str(count_info))
    summary_table.add_row("", "")
    summary_table.add_row("Status", status_str)

    summary_panel = Panel(summary_table, title="[bold]SCAN SUMMARY[/bold]", expand=False, border_style="dim")
    logger.console.print(summary_panel)
    logger.blank()

    scan_findings.sort(key=lambda x: float(x.get("cvss_estimate", 0)), reverse=True)
    scan_result["findings"] = scan_findings

    return {"status": "success", "data": scan_result}


def main():
    
    arg_parser = argparse.ArgumentParser(description="Sinful AI-Based SAST")
    arg_parser.add_argument("target", help="Target directory OR Git URL to scan")
    arg_parser.add_argument("--rules", nargs="+", help="Specific Semgrep rules to use")
    arg_parser.add_argument("--model", type=str, help="Specific AI model to use for review")
    cli_args = arg_parser.parse_args()

    scan_result = run_sast(cli_args.target, cli_args.rules, cli_args.model)

    if scan_result["status"] == "error":
        print(scan_result["message"])
        sys.exit(1)


if __name__ == "__main__":
    main()
