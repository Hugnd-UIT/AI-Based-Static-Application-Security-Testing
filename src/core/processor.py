import os
import json
import time
import textwrap
from cli.views.logger import console
from src.scan.agents import models as scan_agents
from src.audit.agents import models as audit_agents
from cli.views import logger

def broke(txt: str) -> bool:
    low = str(txt).lower()

    return (
        "did not complete" in low
        or "quota" in low
        or "http error" in low
        or "rate limit" in low
        or "429" in low
    )

def process_flaws(flaws, agent_name, sdir, ctx, use_module, cache, res, model, fix=False):
    if not flaws:
        return

    for idx, item in enumerate(flaws):
        console.print(f"  Working [bold]{idx+1}/{len(flaws)}[/bold]")
        console.print(f"  └─ [blue]{item['path']}[/blue]")
        
        try:
            fpath = str(sdir / item["path"]) if item["path"] != str(sdir) else str(sdir)
            ast = use_module.extract_context(fpath, item["start_line"], item["end_line"], dir=str(sdir))

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
                
                if trace and trace.get("flow"):
                    item["dataflow_trace"] = json.dumps(trace["flow"], indent=2)
                    hops = len(trace["flow"])

                    if trace.get("source_variable") or trace.get("sink_function"):
                        console.print(f"  ├─ [cyan]◆ Source:[/cyan] [dim]{trace.get('source_variable', 'Unknown')}[/dim]")
                        console.print(f"  ├─ [cyan]◆ Sink:[/cyan] [dim]{trace.get('sink_function', 'Unknown')}[/dim]")

                        for hop in trace["flow"]:
                            console.print(f"  │  [dim]Hop {hop.get('step')}: {hop.get('variable')} -> {hop.get('operation')}[/dim]")

                    console.print(f"  └─ [bold green]✔ {hops} Hops[/bold green]")
                    break
                
                # Surrogate check
                elif trace and trace.get("surrogate"):
                    surr = trace.get("surrogate_function", "Unknown")
                    item["sink_context"] = f"Original sink was unreachable. We are now treating '{surr}' as the sink. Use find_callers('{surr}') if needed."
                    rcount += 1
                    console.print(f"  ├─ [red]⚠ Flow broken: {surr} - retry {rcount}/{retries}[/red]")
                    
                else:
                    item["dataflow_trace"] = "No trace available"
                    console.print(f"  └─ [bold yellow]⚠ Data flow untraceable[/bold yellow]")
                    break
            
            if rcount >= retries:
                item["dataflow_trace"] = "No trace available"
                console.print(f"  └─ [bold yellow]⚠ Data flow untraceable after {retries} retries[/bold yellow]")

        except Exception as e:
            console.print(f"  └─ [bold red]✖ Tracing failed: {e}[/bold red]")
            item["dataflow_trace"] = f"Trace Error: {e}"

        vuln = False

        # Cache key
        sink_fn = trace.get("sink_function", "") if trace else ""

        # Normalize sink
        if sink_fn:
            sink_fn = sink_fn.strip().split(".")[-1]
        
        # Get source fn
        try:
            fpath = str(sdir / item["path"]) if item["path"] != str(sdir) else str(sdir)
            source_fn = use_module.get_function_at(fpath, item["start_line"])
        except Exception:
            source_fn = "Unknown"

        key = (os.path.basename(item.get('path', '')).lower(), source_fn, sink_fn)

        # Partial key
        partial_key = (os.path.basename(item.get('path', '')).lower(), source_fn)

        if (key in cache and sink_fn) or (not sink_fn and partial_key in cache):
            # Skip duplicate
            reason = f"duplicate sink '{sink_fn}'" if sink_fn else f"same source '{source_fn}'"
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

            # Retry audit
            if verdict_str == "UNKNOWN" and "did not complete" in str(verdict.get("reasoning", "")):
                why = str(verdict.get("reasoning", "")).lower()

                # Skip quota error
                if "quota" in why:
                    console.print("  ├─ [dim]↷ Skip retry, daily token quota exhausted[/dim]")

                else:
                    console.print("  ├─ [dim]↻ Something wrong, retrying[/dim]")

                    # Cooldown
                    time.sleep(10)

                    verdict = audit_agents.start_audit(
                        item, ast, ctx,
                        model=model,
                        target=str(sdir),
                        module=use_module,
                    )
                    verdict_str = verdict.get("verdict", "UNKNOWN").upper()

            # Prune FP
            prune = ""

            if verdict.get("fp_source"):
                prune = "source is not attacker controlled"

            elif verdict.get("fp_sink"):
                prune = "sink is not dangerous in this call"

            if prune and verdict_str == "VULNERABLE":
                verdict["verdict"] = "SAFE"
                verdict_str = "SAFE"
                console.print(f"  ├─ [dim]↷ False positive: {prune}[/dim]")

            vuln = verdict_str == "VULNERABLE"
            reason = verdict.get("reason", "")

            if reason:
                width = max(60, console.width - 10)
                for line in textwrap.wrap(reason, width=width):
                    console.print(f"  │  [dim]{line}[/dim]")

            conf = verdict.get("confidence", 0)
            if vuln:
                console.print(f"  ├─ [bold red]✖ VULNERABLE[/bold red]")
                console.print(f"  ├─ [dim][CVSS: {verdict.get('cvss', 'N/A')}] [{verdict.get('severity', 'UNKNOWN')}][/dim]")
                console.print(f"  ├─ [dim][Confidence: {verdict.get('confidence', 'N/A')}%][/dim]")
                res["vuln"] = True
                vuln = True
                item.update(verdict)

                # Fallback flow
                if not item.get("flow") and trace.get("flow"):
                    item["flow"] = trace["flow"]

                # Remove redundant
                fields_to_drop = [
                    "ast", "dataflow_trace", "sink_context"
                ]
                for field in fields_to_drop:
                    item.pop(field, None)

                if sink_fn:
                    cache[key] = verdict
                # Cache partial key
                cache[partial_key] = verdict

            elif verdict_str == "SAFE":
                console.print(f"  └─ [bold green]✓ SAFE[/bold green] [dim][Confidence: {conf}%][/dim]")
            else:
                console.print(f"  └─ [bold yellow]⚠ UNKNOWN[/bold yellow]")

                # Mark unverified
                if broke(verdict.get("reason", "")) or broke(verdict.get("reasoning", "")):
                    res["unverified"] = res.get("unverified", 0) + 1

        except Exception as e:
            console.print(f"  ├─ [bold red]✖ Audit Agent failed: {e}[/bold red]")
            res["unverified"] = res.get("unverified", 0) + 1

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
                    console.print(f"  └─ [bold yellow]⚠ Failed to fix[/bold yellow]")

            except Exception as e:
                console.print(f"  └─ [bold red]✖ Fix Agent failed: {e}[/bold red]")

        logger.blank()