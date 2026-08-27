import os
import json
import time
import textwrap
from concurrent.futures import ThreadPoolExecutor, as_completed
from cli.views.logger import console
from cli.views import logger

from src.rag import osv
from src.rag import nvd
from src.rag import firecrawl
from src.rag import github
from src.rag.agents import models as rag_agents
from src.core.processor import process_flaws

def run_sca(deps, sdir, use_module, res, model, cache, fix):
    sca_flaws = []
    cves = []
    hot = []
    parts = []
    
    if deps:
        try:
            cves = osv.check_osv(deps)
        except AttributeError:
            cves = []

        from src.rag import usage
        cves = usage.check_usage(str(sdir), cves, use_module)

        # Dep khai báo trong manifest mà có cve thì vẫn phải báo, reachable chỉ dùng để chọn cái đem đi phân tích sâu
        res["cves"] = cves
        osv.report_osv(cves)

        hot = []

        # Phân tích sâu tốn nhiều request nên chặn trần và dàn đều theo package để repo nhiều dep không chạy hàng giờ
        cap = int(os.getenv("SINFUL_SCA_DEEP") or "10")
        per = {}

        for cve in cves:
            if not cve.get("reachable", True):
                continue

            pkg = str(cve.get("package", "")).lower()

            if len(hot) >= cap or per.get(pkg, 0) >= 2:
                continue

            per[pkg] = per.get(pkg, 0) + 1
            hot.append(cve)

        scves = set()
        for cve in hot:
            for alias in cve.get("cve", []):
                if str(alias).startswith("CVE-"):
                    scves.add(alias)

        if scves:
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

            # Mỗi cve tốn 1 nvd + 2 firecrawl + 1 github nên chạy song song cho đỡ lâu
            ids = list(scves)
            done = {}

            with ThreadPoolExecutor(max_workers=5) as pool:
                jobs = {pool.submit(fetch_cve, cid): cid for cid in ids}

                for num, job in enumerate(as_completed(jobs), 1):
                    cid = jobs[job]
                    console.print(f"  [dim]Enriching {num}/{len(ids)} {cid}[/dim]")

                    try:
                        done[cid] = job.result()
                    except Exception as e:
                        console.print(f"  [dim]Failed to fetch {cid}: {e}[/dim]")

            for cid in ids:
                nres = done.get(cid)
                if nres:
                    console.print("")
                    nvd.report_nvd(nres)
                    res["nvd"].append(nres)

    parts = []
    tag = fr" [[cyan]{model}[/cyan]]"
    
    if res["nvd"] or hot:
        pcves = []
        fnvd = {n.get("cve_id"): n for n in res.get("nvd", []) if n.get("cve_id")}

        for base in hot:
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
                rsum = rag_agents.start_rag(jstr, model=model) # RAG Agent Role
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
                ctx_verify = cjson
                
                role = model
                tstr = rsum.get("ccve", "Unknown CVE")
                console.print(f"\n  [bold magenta]● VERIFYING AGENT[/bold magenta] [[cyan]{role}[/cyan]]")
                console.print(f"  ├─ [cyan]◆ Target: {tstr}[/cyan]")
                from src.rag.agents import verifier
                poc = verifier.start_verify(ctx_verify, model=role, target=str(sdir), module=use_module)
                
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
                                
                    ctx_verify += "\nNOTE: PoC Verifier determined this CVE is NOT exploitable in the current codebase."

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
                    
                    expand = model
                    console.print(f"\n  [bold magenta]● EXPANDING AGENT[/bold magenta] [[cyan]{expand}[/cyan]]")
                    console.print(f"  ├─ [cyan]◆ Target: {tstr}[/cyan]")
                    from src.rag.agents import expander
                    exp = expander.start_expand(ctx_verify, model=expand, target=str(sdir), module=use_module)

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
                                                parts_line = line.strip().split(":", 2)
                                                if len(parts_line) >= 2:
                                                    gfile = parts_line[0]
                                                    try:
                                                        num = int(parts_line[1])
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
        logger.section("SCA")
        console.print(f"  [bold magenta]● RAG AGENT[/bold magenta]{tag}")
        console.print("  └─ [dim]No vulnerabilities found! Skip![/dim]")

    ctx_final = "\n\n---\n\n".join(parts) if parts else "No relevant supply chain vulnerabilities found in project dependencies."
    if cves:
        res['cves'] = cves
    process_flaws(sca_flaws, 'SCA', sdir, ctx_final, use_module, cache, res, model, fix)
    
    return sca_flaws
