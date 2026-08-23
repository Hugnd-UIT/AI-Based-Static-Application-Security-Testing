import json
import subprocess
from pathlib import Path
from typing import Dict, List, Any

RULES = [
    # Bộ quy tắc tiêu chuẩn
    "p/owasp-top-ten",
    "p/security-audit",
    "p/secrets",
    "p/default",

    # Nhóm lỗ hổng bảo mật
    "p/xss",
    "p/sql-injection",
    "p/command-injection",
    "p/insecure-transport",
    "p/supply-chain",

    # Nhóm Ngôn ngữ & Framework
    "p/python",
    "p/django",
    "p/flask",
    "p/fastapi",
    "p/nodejs",
    "p/javascript",
    "p/typescript",
    "p/react",
    "p/java",
    "p/golang",
    "p/php",
    "p/ruby",
    "p/c",

    # Nhóm quy tắc đặc thù
    "p/trailofbits",
    "p/jwt",
]

# Hàm quét mã nguồn
def scan_code(target: str, rules: List[str] = None) -> List[Dict[str, Any]]:
    path = Path(target)

    # Kiểm tra đường dẫn
    if not path.exists() or not path.is_dir():
        raise ValueError(f"[!] The path is invalid: {target}")

    rules = rules if rules else RULES
    
    import sys
    import os
    
    # Kiểm tra semgrep
    python = Path(sys.executable).parent
    binary = "semgrep.exe" if os.name == "nt" else "semgrep"
    exe = python / binary

    if not exe.exists():
        import shutil
        exe = shutil.which(binary) or binary
    else:
        exe = str(exe)

    # Cấu hình semgrep
    cmd = [exe, "scan", "--json", "--quiet", "--no-git-ignore"]

    for rule in rules:
        cmd.extend(["--config", rule])

    custom = Path(__file__).parent / "rules"

    if custom.exists() and custom.is_dir():
        cmd.extend(["--config", str(custom)])

    cmd.append(str(path))
    
    try:
        # Khởi động semgrep
        env = os.environ.copy()
        env["SEMGREP_SEND_METRICS"] = "off"
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600, env=env)

        output = result.stdout.strip()

        # Kiểm tra kết quả
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

        # Làm sạch kết quả
        for item in findings:
            file = item.get("path")
            line = item.get("start", {}).get("line")
            
            key = f"{file}:{line}"

            if key in seen:
                continue

            seen.add(key)

            extra = item.get("extra", {})
            meta = extra.get("metadata", {})

            clean = {
                "id": item.get("check_id"),
                "path": item.get("path"),
                "start_line": item.get("start", {}).get("line"),
                "start_col": item.get("start", {}).get("col"),
                "end_line": item.get("end", {}).get("line"),
                "end_col": item.get("end", {}).get("col"),
                "severity": extra.get("severity"),
                "message": extra.get("message"),
                "lines": extra.get("lines"),
                "cwe": meta.get("cwe", []),
                "owasp": meta.get("owasp", []),
                "category": meta.get("category", ""),
                "technology": meta.get("technology", []),
                "confidence": meta.get("confidence", ""),
                "impact": meta.get("impact", ""),
                "likelihood": meta.get("likelihood", ""),
                "references": meta.get("references", []),
                "shortlink": meta.get("shortlink", ""),
                "vulnerability_class": meta.get("vulnerability_class", []),
                "dataflow_trace": extra.get("dataflow_trace"),
                "fix": extra.get("fix"),
                "fix_regex": extra.get("fix_regex")
            }

            cleaned.append(clean)

        return cleaned

    except subprocess.TimeoutExpired:
        print("[!] Semgrep timed out")
        return []

    except json.JSONDecodeError:
        print("[!] Failed to parse Semgrep output")
        return []

    except FileNotFoundError:
        print("[!] Semgrep not found. Please run: pip install semgrep")
        return []
        
    except PermissionError:
        print("[!] Permission denied when running Semgrep")
        return []

from cli.views import logger

# Hàm báo cáo kết quả
def report_scan(findings: List[Dict[str, Any]]):
    from cli.views.logger import console

    if not findings:
        console.print("  [green]- No vulnerabilities detected[/green]")
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