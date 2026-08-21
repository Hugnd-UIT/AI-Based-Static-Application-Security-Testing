import sys
import os
import subprocess
import argparse
from pathlib import Path

# Thư mục gốc của project
root = Path(__file__).resolve().parent.parent.parent
sys.path.append(str(root))

try:
    from rich.console import Console
    from rich.panel import Panel
    console = Console()

except ImportError:
    print("Error: Required 'rich' library is not installed.")
    sys.exit(1)

# In header màn hình
def show_header():
    console.print()
    console.print(Panel(
        "[bold cyan]SINFUL SAST - CD[/bold cyan]\n[dim]Continuous Deployment[/dim]",
        border_style="cyan",
        expand=False
    ))
    console.print()

# In lỗi khi triển khai thất bại
def show_failure(cmd, code, msg):
    console.print("[cyan]━ ━ ━  CD WORKFLOW ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ [/cyan]\n")
    console.print("Environment     [green]✔ VERIFIED[/green]")

    if cmd:
        console.print(f"Command         [dim]{cmd}[/dim]")
    console.print("Preparation     [green]✔ COMPLETED[/green]")
    console.print("Deployment      [red]✖ FAILED[/red]")
    console.print("Deployment Gate [red]✖ FAILED[/red]\n")
    console.print("[cyan]━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ [/cyan]\n")
    console.print("[bold red]✖ CD WORKFLOW FAILED[/bold red]\n")
    console.print(f"{msg}")
    console.print("Deployment stopped.\n")
    console.print(f"[dim]Exit code: {code}[/dim]")
    sys.exit(code)

# Chạy lệnh triển khai
def run_cd(cmd):
    show_header()

    if not cmd:
        console.print("[cyan]━ ━ ━  CD WORKFLOW ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ [/cyan]\n")
        console.print("[red]✖ Deployment command not provided.[/red]\n")
        console.print("Usage:\n[dim]python cli/pipeline/cd.py --cmd \"<deployment-command>\"[/dim]")
        sys.exit(0)
        
    console.print("[cyan]━ ━ ━  CD WORKFLOW ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ [/cyan]\n")
    console.print("Environment     [green]✔ VERIFIED[/green]")
    console.print(f"Command         [dim]{cmd}[/dim]")
    console.print("Preparation     [green]✔ COMPLETED[/green]")
    console.print("Deployment      [cyan]● RUNNING[/cyan]\n")

    try:
        # Chạy process
        proc = subprocess.Popen(
            cmd, 
            shell=True, 
            stdout=sys.stdout, 
            stderr=sys.stderr
        )
        proc.communicate()
        
        # Kiểm tra kết quả
        if proc.returncode != 0:
            console.print()
            show_failure(cmd, proc.returncode, f"Deployment command exited with code {proc.returncode}.")

        else:
            console.print("\n[cyan]━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ [/cyan]\n")
            console.print("Deployment Gate [green]✔ PASSED[/green]\n")
            console.print("[cyan]━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ [/cyan]\n")
            console.print("[bold green]✔ CD WORKFLOW PASSED[/bold green]\n")
            console.print("Deployment completed successfully.\n")
            console.print("[dim]Exit code: 0[/dim]")
            
    except Exception as err:
        console.print()
        show_failure(cmd, 1, f"Deployment encountered an error: {err}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sinful SAST CD Wrapper")
    parser.add_argument("--cmd", type=str, help="Actual deployment command to run (e.g., 'npx vercel --prod')", default="")
    args = parser.parse_args()
    
    run_cd(args.cmd)
