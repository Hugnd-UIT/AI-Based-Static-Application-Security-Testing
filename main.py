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

def run_sast(target_path, rule_list=None, model=None):
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
    scan_result["languages"] = language_counts
    detector.report(language_counts)

    parsed_deps = dep_parser.parse(str(target_dir))
    scan_result["dependencies"] = parsed_deps
    dep_parser.report(parsed_deps)

    scan_findings = semgrep.scan(str(target_dir), rule_list)
    scan_result["findings"] = scan_findings
    semgrep.report(scan_findings)

    if not scan_findings:
        return {"status": "success", "message": "No vulnerabilities found.", "data": scan_result}

    if parsed_deps:
        try:
            cve_list = osv.check(parsed_deps)
        except AttributeError:
            cve_list = osv.fetch(parsed_deps)

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
    
    if scan_result["cves"] or scan_result["nvd_data"]:
        cve_data_str = json.dumps({"osv": scan_result["cves"], "nvd": scan_result["nvd_data"]}, indent=2)
        from cli.views.logger import console
        console.print("  [dim]Running RAG Agent to summarize vulnerabilities...[/dim]")
        try:
            rag_summary = rag_agents.fetch(cve_data_str, model=model)
            cve_context = json.dumps(rag_summary, indent=2)
            console.print("  [bold green]✔ RAG Summary generated.[/bold green]")
        except Exception as e:
            console.print(f"  [bold red]✖ RAG Agent failed: {e}[/bold red]")
            cve_context = cve_data_str

    critical_findings = [find_item for find_item in scan_findings if find_item["severity"] == "ERROR"]
    
    if not critical_findings:
        pass
    else:
        logger.section("MULTI-AGENT")

        for loop_idx, finding_item in enumerate(critical_findings):
            logger.console.print(f"  Reviewing [bold]{loop_idx+1}/{len(critical_findings)}[/bold]")
            logger.console.print(f"  ├─ [blue]{finding_item['path']}[/blue]")
            logger.blank()
            
            try:
                finding_path = str(target_dir / finding_item["path"])
                ast_context = ts_module.extract_context(finding_path, finding_item["start_line"], finding_item["end_line"], target_dir=str(target_dir))
            except Exception as ext_err:
                ast_context = f"Error extracting AST context: {ext_err}"

            try:
                logger.console.print(f"  ├─ [dim]Tracing Data Flow (Agent 2)...[/dim]")
                trace_json = scan_agents.fetch(finding_item, ast_context, model=model)
                if trace_json and "data_flow" in trace_json:
                    finding_item["dataflow_trace"] = json.dumps(trace_json["data_flow"], indent=2)
                    hops_count = len(trace_json["data_flow"])
                    logger.console.print(f"  ├─ [bold green]✔ Traced {hops_count} data hops.[/bold green]")
                else:
                    finding_item["dataflow_trace"] = "No trace available (Scan Agent failed to identify flow)."
                    logger.console.print(f"  ├─ [bold yellow]⚠ Data flow untraceable.[/bold yellow]")
            except Exception as e:
                logger.console.print(f"  ├─ [bold red]✖ Data Flow Tracing failed: {e}[/bold red]")
                finding_item["dataflow_trace"] = f"Trace Error: {e}"

            try:
                fetch_result = agents.fetch(finding_item, ast_context, cve_context, model=model)
                if isinstance(fetch_result, tuple):
                    ai_review, model_name = fetch_result
                    logger.console.print(f"  ├─ [magenta][AI - {model_name}][/magenta]")
                else:
                    ai_review = fetch_result
            except AttributeError:
                ai_review = agents.review_finding(finding_item, ast_context, cve_context)

            is_first_line = True
            for text_line in ai_review.split("\n"):
                text_line = text_line.strip()
                if not text_line:
                    continue
                
                line_lower = text_line.lower()
                clean_lower = line_lower.replace("*", "").replace("#", "").strip()
                
                if clean_lower.startswith("step "):
                    verdict_title = text_line.replace("*", "").replace("###", "").strip()
                    logger.console.print(f"  [cyan]◆ {verdict_title}[/cyan]")
                    is_first_line = True
                elif clean_lower.startswith("final verdict") or "final verdict" in clean_lower:
                    verdict_title = text_line.replace("*", "").replace("###", "").strip()
                    if not verdict_title.lower().startswith("final"):
                        verdict_title = "Final Verdict"
                    logger.console.print(f"  [cyan]◆ {verdict_title}[/cyan]")
                    is_first_line = True
                elif text_line.startswith("[VULNERABLE]") or "VULNERABLE" in text_line:
                    logger.console.print("  [bold red]✖ VULNERABLE[/bold red]")
                    scan_result["is_vulnerable"] = True
                elif text_line.startswith("[SAFE]") or "SAFE" in text_line:
                    logger.console.print("  [bold green]✓ SAFE[/bold green]")
                else:
                    if text_line.startswith("* ") or text_line.startswith("- "):
                        text_line = text_line[2:]
                    
                    if is_first_line:
                        logger.console.print(f"  └─ [dim]{text_line}[/dim]")
                        is_first_line = False
                    else:
                        logger.console.print(f"     [dim]{text_line}[/dim]")

            logger.blank()
            scan_result["ai_reviews"].append({"finding": finding_item, "review": ai_review})

            if loop_idx < len(critical_findings) - 1:
                time.sleep(20)

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
