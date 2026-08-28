import os
from cli.views.logger import console
from cli.views import logger

from src.scan import semgrep
from src.scan.semgrep import pick_rules
from src.scan.agents.extractor import extract_functions
from src.scan.agents.classifier import classify
from src.scan.agents.generator import generate
from src.core.processor import process_flaws

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

def run_sast(sdir, rules, model, ctx, use_module, cache, res, fix):
    sgres = []

    try:
        logger.section("SAST")
        console.print(f"  [bold magenta]● GENERATING AGENT[/bold magenta]")

        # Remove stale rules
        stale = os.path.join(str(sdir), "custom-rules.yml")
        if os.path.exists(stale):
            os.remove(stale)

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
                    rules = pick_rules(res.get("languages", {}))
                elif isinstance(rules, str):
                    rules = [rules]
                    
                rules.append(dynamic_rule_path)
            else:
                console.print("  └─ [dim]No rules generated[/dim]")

        else:
            console.print("  └─ [dim]No APIs extracted[/dim]")

    except Exception as e:
        console.print(f"  └─ [bold red]✖ Generate Agent failed: {e}[/bold red]")

    # Pick rules by language
    if rules is None:
        rules = pick_rules(res.get("languages", {}))

    sgres = semgrep.scan_code(str(sdir), rules)
    
    # Inject direct vulnerabilities
    if 'classifications' in locals() and classifications:
        for item in classifications:
            if item.get('type') == 'vuln':
                sgres.append({
                    "id": f"dynamic-rule-{item.get('function')}",
                    "message": f"AI Classifier detected structural vulnerability in {item.get('function')}",
                    "path": os.path.join(str(sdir), item.get('file', '')),
                    "start_line": item.get('start_line', 1),
                    "end_line": item.get('end_line', 2),
                    "severity": "HIGH",
                    "dataflow_trace": "[DIRECT VULNERABILITY DETECTED]\nNo taint path required. Structural defect found in function body."
                })

    sgres = deduplicate(sgres)

    console.print(f'  └─ [bold green]✔ Scan completed: {len(sgres)} vulnerabilities[/bold green]')
    
    semgrep.report_scan(sgres)
    
    process_flaws(sgres, 'SAST', sdir, ctx, use_module, cache, res, model, fix)
    
    return sgres