import json
import subprocess
from pathlib import Path
from typing import Dict, List, Any
from typing import Dict, List, Any

CORE = [
    "p/owasp-top-ten",
    "p/security-audit",
    "p/secrets",
    "p/default",
]

LANG = {
    "python": ["p/python", "p/django", "p/flask", "p/fastapi"],
    "javascript": ["p/javascript", "p/nodejs", "p/react"],
    "typescript": ["p/typescript", "p/nodejs", "p/react"],
    "java": ["p/java", "p/jwt"],
    "go": ["p/golang"],
    "php": ["p/php"],
    "ruby": ["p/ruby"],
    "rust": ["p/rust"],
    "scala": ["p/scala"],
    "c": ["p/c", "p/trailofbits"],
    "c++": ["p/c", "p/trailofbits"],
    "c#": ["p/csharp"],
}

EXTRA = [
    "p/xss",
    "p/sql-injection",
    "p/command-injection",
    "p/insecure-transport",
    "p/supply-chain",
]

RULES = CORE + EXTRA + sorted({r for rs in LANG.values() for r in rs})

# Pick rules based on detected languages
def pick_rules(langs) -> List[str]:
    if not langs:
        return list(RULES)

    picked = list(CORE)

    for lang in langs:
        for rule in LANG.get(str(lang).lower(), []):
            if rule not in picked:
                picked.append(rule)

    return picked

def scan_code(target: str, rules: List[str] = None) -> List[Dict[str, Any]]:
    path = Path(target)

    # Check path
    if not path.exists() or not path.is_dir():
        raise ValueError(f"[!] The path is invalid: {target}")

    rules = rules if rules else RULES
    
    import sys
    import os
    
    # Check semgrep binary
    python = Path(sys.executable).parent
    binary = "semgrep.exe" if os.name == "nt" else "semgrep"
    exe = python / binary

    if not exe.exists():
        import shutil
        exe = shutil.which(binary) or binary
    else:
        exe = str(exe)

    # Configure semgrep
    cmd = [exe, "scan", "--json", "--quiet", "--no-git-ignore"]

    for rule in rules:
        cmd.extend(["--config", rule])

    custom = Path(__file__).parent / "rules"

    if custom.exists() and custom.is_dir():
        cmd.extend(["--config", str(custom)])

    cmd.append(str(path))
    
    try:
        # Start semgrep
        env = os.environ.copy()
        env["SEMGREP_SEND_METRICS"] = "off"
        
        result = subprocess.run(cmd, capture_output=True, text=True, env=env)

        output = result.stdout.strip()

        # Check results
        if not output:
            if hasattr(result, "stderr") and result.stderr.strip():
                print(f"[!] Semgrep failed: {result.stderr.strip()}")
            return []
            
        start = output.find('{')

        if start != -1:
            output = output[start:]

        data = json.loads(output)
        findings = data.get("results", [])

        cleaned = []
        seen = set()

        # Clean results
        for item in findings:
            file = item.get("path")
            line = item.get("start", {}).get("line")
            
            key = f"{file}:{line}"

            if key in seen:
                continue

            seen.add(key)

            extra = item.get("extra", {})
            meta = extra.get("metadata", {})

            # Remove semgrep path prefix added to dynamic rule IDs
            rid = item.get("check_id") or ""
            if "dynamic-rule-" in rid:
                rid = rid[rid.index("dynamic-rule-"):]

            clean = {
                "id": rid,
                "path": item.get("path"),
                "start_line": item.get("start", {}).get("line"),
                "end_line": item.get("end", {}).get("line"),
                "severity": extra.get("severity"),
                "message": extra.get("message"),
                "cwe": meta.get("cwe", []),
                "confidence": meta.get("confidence", ""),
                "references": meta.get("references", []),
                "class": meta.get("vulnerability_class", []),
                "dataflow_trace": extra.get("dataflow_trace"),
                "fix": extra.get("fix"),
                "regex": extra.get("fix_regex")
            }

            cleaned.append(clean)

        return cleaned

    except json.JSONDecodeError:
        print("[!] Failed to parse semgrep output")
        return []

    except FileNotFoundError:
        print("[!] Semgrep not found!")
        return []
        
    except PermissionError:
        print("[!] Permission denied!")
        return []

from cli.views import logger

# Report scan results function
def report_scan(findings: List[Dict[str, Any]]):
    from cli.views.logger import console

    if not findings:
        console.print("  [green][!] No vulnerabilities detected[/green]")
        return

    console.print(f"  [bold]{len(findings)} vulnerabilities detected[/bold]")
    console.print()

    for item in findings:
        severity = item.get("severity") or "WARNING"
        rule = item["id"]
        file = item["path"]
        line = item["start_line"]

        level = severity.upper()

        if level in ["ERROR", "CRITICAL", "HIGH"]:
            color = "red"

        elif level in ["WARNING", "MEDIUM"]:
            color = "yellow"

        else:
            color = "cyan"

        console.print(f"  ┌─ [bold {color}]{severity}[/bold {color}]")
        console.print(f"  ├─ Rule   [cyan]{rule}[/cyan]")
        console.print(f"  ├─ File   [dim]{file}[/dim]")
        console.print(f"  └─ Line   [bold yellow]{line}[/bold yellow]")
        console.print()