import os
import json
import textwrap
from cli.views.logger import console
from src.scan.agents import models as scan_agents
from src.audit.agents import models as audit_agents
from cli.views import logger

def process_flaws(flaws, agent_name, sdir, ctx, use_module, cache, res, model, fix=False):
    if not flaws:
        return

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
            logger.blank()
            
            retries = 2
            rcount = 0
            trace = {}
            
            console.print(f"  [bold magenta]● SCANNING AGENT[/bold magenta] [[cyan]{model}[/cyan]]")
            
            while rcount < retries:
                trace = scan_agents.start_scan(
                    item, ast,
                    model=model, # Scanning Agent Role
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
                    console.print(f"  ├─ [red]⚠ Flow broken: {surr} - retry {rcount}/{retries}[/red]")
                    
                else:
                    item["dataflow_trace"] = "No trace available"
                    console.print(f"  └─ [bold yellow]⚠ Data flow untraceable[/bold yellow]")
                    break
            
            if rcount >= retries:
                item["dataflow_trace"] = "No trace available (max retries reached)"
                console.print(f"  └─ [bold yellow]⚠ Data flow untraceable after {retries} retries[/bold yellow]")

        except Exception as e:
            console.print(f"  └─ [bold red]✖ Data Flow Tracing failed: {e}[/bold red]")
            item["dataflow_trace"] = f"Trace Error: {e}"

        vuln = False

        # Build cache key from AI-determined sink and the surrounding function
        sink_fn = trace.get("sink_function", "") if trace else ""
        # Normalize: "SqlCommand.ExecuteReader" → "ExecuteReader" to handle AI inconsistency
        if sink_fn:
            sink_fn = sink_fn.strip().split(".")[-1]
        
        # Get source function using tree-sitter to avoid false negatives in same file
        try:
            fpath = str(sdir / item["path"]) if item["path"] != str(sdir) else str(sdir)
            source_fn = use_module.get_function_at(fpath, item["start_line"])
        except Exception:
            source_fn = "Unknown"

        key = (os.path.basename(item.get('path', '')).lower(), source_fn, sink_fn)
        # Fallback partial key used when scan fails to identify sink (sink_fn="")
        partial_key = (os.path.basename(item.get('path', '')).lower(), source_fn)

        if (key in cache and sink_fn) or (not sink_fn and partial_key in cache):
            # Duplicate detected — skip audit entirely
            reason = f"duplicate sink '{sink_fn}'" if sink_fn else f"same source fn '{source_fn}' already audited"
            console.print(f"  [dim]↷ Skipped {reason}[/dim]")
            logger.blank()
            continue


        try:
            logger.blank()
            console.print(f"  [bold magenta]● AUDITING AGENT[/bold magenta] [[cyan]{model}[/cyan]]")

            verdict = audit_agents.start_audit(
                item, ast, ctx,
                model=model,
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
                console.print(f"  ├─ [bold red]✖ VULNERABLE[/bold red]")
                console.print(f"  ├─ [dim][CVSS: {verdict.get('cvss_estimate', 'N/A')}] [{verdict.get('severity', 'UNKNOWN')}][/dim]")
                console.print(f"  ├─ [dim][Confidence: {verdict.get('confidence', 'N/A')}%][/dim]")
                if "cwe_ids" in verdict:
                    console.print(f"  ├─ [dim][CWEs: {verdict.get('cwe_ids', [])}][/dim]")
                console.print(f"  └─ [dim][Class: {verdict.get('vuln_class', 'N/A')}][/dim]")
                res["vuln"] = True
                vuln = True
                item.update(verdict)

                if sink_fn:
                    cache[key] = verdict
                # Always store partial_key so scan-failed duplicates are caught
                cache[partial_key] = verdict

            elif verdict_str == "SAFE":
                console.print(f"  └─ [bold green]✓ SAFE[/bold green] [dim][Confidence: {conf}%][/dim]")
            else:
                console.print(f"  └─ [bold yellow]⚠ UNKNOWN[/bold yellow]")

        except Exception as e:
            console.print(f"  ├─ [bold red]✖ Auditor Agent failed: {e}[/bold red]")

        if fix:
            try:
                logger.blank()
                console.print(f"  [bold magenta]● FIXING AGENT[/bold magenta] [[cyan]{model}[/cyan]]")
                from src.fix.agents import models as ufix
                fixres = ufix.start_fix(
                    item, ast, ctx,
                    model=model,
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
