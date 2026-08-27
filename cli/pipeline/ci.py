import sys
import os
import argparse
import json
from pathlib import Path

# Cấu hình đường dẫn gốc
root = Path(__file__).resolve().parent.parent.parent
sys.path.append(str(root))

try:
    from main import run_scan
    from cli.views import logger
    from rich.panel import Panel

except ImportError as err:
    print(f"Error: Cannot import the main module of Sinful SAST: {err}")
    sys.exit(2)

# Đổi mức độ nghiêm trọng sang mức của SARIF
def sev_level(find: dict) -> str:
    sev = (find.get("severity") or "").upper()

    if sev in ("CRITICAL", "HIGH", "ERROR"):
        return "error"

    if sev in ("MEDIUM", "WARNING"):
        return "warning"

    return "note"

# GitHub chỉ map được alert khi uri là đường dẫn tương đối so với gốc repo
def rel_path(path: str) -> str:
    try:
        rel = os.path.relpath(str(path), os.getcwd())

    except Exception:
        rel = str(path)

    return rel.replace("\\", "/")

# Tạo báo cáo định dạng SARIF
def gen_sarif(finds, out):
    rules = {}
    res = []

    # Duyệt qua các lỗi
    for find in finds:
        rid = find.get("id") or find.get("check_id") or find.get("rule_id", "VULN-001")

        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "shortDescription": {"text": find.get("title") or find.get("message") or rid},
                "fullDescription": {"text": find.get("description") or find.get("message", "Security vulnerability detected.")},
                "defaultConfiguration": {"level": sev_level(find)}
            }

        path = rel_path(find.get("path") or find.get("file", "unknown"))
        line = find.get("start_line") or find.get("start") or find.get("line") or getattr(find.get("start"), "line", 1)

        if isinstance(line, dict):
            line = line.get("line", 1)

        sres = {
            "ruleId": rid,
            "level": sev_level(find),
            "message": {"text": find.get("extra", {}).get("message") or find.get("message", "Vulnerability found")},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": path},
                        "region": {"startLine": line}
                    }
                }
            ]
        }
        res.append(sres)
        
    sdata = {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Sinful SAST",
                        "informationUri": "https://github.com/Hugnd-UIT/AI-Based-Static-Application-Security-Testing",
                        "rules": list(rules.values())
                    }
                },
                "results": res
            }
        ]
    }
    
    # Ghi file báo cáo
    with open(out, "w", encoding="utf-8") as file:
        json.dump(sdata, file, indent=2)

# Chạy quy trình CI
def run_ci():
    parser = argparse.ArgumentParser(description="Sinful SAST CI Scanner")
    parser.add_argument("--exit-code", type=int, default=1, help="Exit code when vulnerabilities are found")
    parser.add_argument("--severity", type=str, default="CRITICAL,HIGH", help="Comma-separated severities to block on")
    parser.add_argument("--format", type=str, default="table", choices=["table", "sarif"], help="Output format")
    parser.add_argument("--output", type=str, default="results.sarif", help="Output file path for sarif")
    args = parser.parse_args()

    # Hiển thị tiêu đề
    if args.format != "sarif":
        logger.console.print()
        logger.console.print(Panel(
            "[bold cyan]SINFUL SAST - CI[/bold cyan]\n[dim]Continuous Integration[/dim]", 
            border_style="cyan", 
            expand=False
        ))
        logger.console.print()
    

    tdir = os.getcwd()

    # Mã 2 dành cho lỗi của chính scanner, tách khỏi mã chặn do có lỗ hổng
    try:
        # Chạy quét bảo mật
        scan = run_scan(tdir)

    except Exception as err:

        if args.format != "sarif":
            logger.console.print("[cyan]━ ━ ━  CI WORKFLOW ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ [/cyan]\n")
            logger.console.print(f"[red]✖ Exception occurred during scanning: {err}[/red]\n")

        else:
            print(f"Scanner error: {err}")
        sys.exit(2)

    # Nếu quét bị lỗi
    if scan.get("status") == "error":

        if args.format != "sarif":
            logger.console.print("[cyan]━ ━ ━  CI WORKFLOW ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ [/cyan]\n")
            logger.console.print(f"[red]✖ Scan failed: {scan.get('message')}[/red]\n")

        else:
            print(f"Scan failed: {scan.get('message')}")
        sys.exit(2)

    data = scan.get("data", {})
    finds = data.get("findings", [])
    lost = data.get("unverified", 0)
    
    # Tạo báo cáo SARIF nếu được yêu cầu
    if args.format == "sarif":
        gen_sarif(finds, args.output)
        print(f"SARIF report generated: {args.output}")
    
    # Kiểm tra mức độ nghiêm trọng
    sevs = [sev.strip().upper() for sev in args.severity.split(",")]
    count = len([f for f in finds if f.get("severity", "").upper() in sevs])
    vuln = count > 0

    # Có điểm nghi vấn không lấy được phán quyết thì chưa kết luận được, để pass là bỏ lọt lỗ hổng
    if not vuln and lost:

        if args.format != "sarif":
            logger.console.print("[cyan]━ ━ ━  CI WORKFLOW ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ [/cyan]\n")
            logger.console.print("Environment     [green]✔ VERIFIED[/green]")
            logger.console.print("Security Scan   [yellow]⚠ INCONCLUSIVE[/yellow]")
            logger.console.print(f"Unverified      [yellow]⚠ {lost}[/yellow]")
            logger.console.print("Security Gate   [yellow]⚠ NO VERDICT[/yellow]\n")
            logger.console.print(f"{lost} finding(s) could not be audited, so the result is not a clean bill of health.\n")
            logger.console.print("[dim]Exit code: 2[/dim]")

        else:
            print(f"Scan inconclusive: {lost} finding(s) had no verdict")
        sys.exit(2)

    if args.format == "sarif":
        sys.exit(args.exit_code if vuln else 0)

    if args.format != "sarif":
        logger.console.print("[cyan]━ ━ ━  CI WORKFLOW ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ [/cyan]\n")
        logger.console.print("Environment     [green]✔ VERIFIED[/green]")
        logger.console.print("Security Scan   [green]✔ COMPLETED[/green]")
        
        # Nếu có lỗi nghiêm trọng
        if vuln:
            logger.console.print(f"Findings        [red]✖ {count}[/red]")
            logger.console.print("Security Gate   [red]✖ FAILED[/red]\n")
            logger.console.print("[cyan]━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ [/cyan]\n")
            logger.console.print("[bold red]✖ CI WORKFLOW FAILED[/bold red]\n")
            
            logger.console.print(f"{count} issue(s) matched the configured severity threshold.")
            logger.console.print("Pipeline blocked.\n")
            logger.console.print(f"[dim]Exit code: {args.exit_code}[/dim]")
            sys.exit(args.exit_code)

        else:
            logger.console.print("Findings        [green]✔ 0[/green]")
            logger.console.print("Security Gate   [green]✔ PASSED[/green]\n")
            logger.console.print("[cyan]━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ [/cyan]\n")
            logger.console.print("[bold green]✔ CI WORKFLOW PASSED[/bold green]\n")
            logger.console.print("No issues matched the configured severity threshold.\n")
            logger.console.print("[dim]Exit code: 0[/dim]")
            sys.exit(0)

if __name__ == "__main__":
    run_ci()

