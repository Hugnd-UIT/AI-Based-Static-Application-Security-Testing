import sys
import os
import subprocess
import argparse
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.append(str(ROOT_DIR))

try:
    from rich.console import Console
    from rich.panel import Panel
    console = Console()

except ImportError:
    print("Error: Required 'rich' library is not installed.")
    sys.exit(1)

def show_header():
    console.print()
    console.print(Panel(
        "[bold cyan]SINFUL SAST - CD[/bold cyan]\n[dim]Continuous Deployment[/dim]",
        border_style="cyan",
        expand=False
    ))
    console.print()

def show_failure(deploy_cmd, exit_code, reason_msg):
    console.print("[cyan]━━━ CD WORKFLOW ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/cyan]\n")
    console.print("Environment     [green]✔ VERIFIED[/green]")

    if deploy_cmd:
        console.print(f"Command         [dim]{deploy_cmd}[/dim]")
    console.print("Preparation     [green]✔ COMPLETED[/green]")
    console.print("Deployment      [red]✖ FAILED[/red]")
    console.print("Deployment Gate [red]✖ FAILED[/red]\n")
    console.print("[cyan]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/cyan]\n")
    console.print("[bold red]✖ CD WORKFLOW FAILED[/bold red]\n")
    console.print(f"{reason_msg}")
    console.print("Deployment stopped.\n")
    console.print(f"[dim]Exit code: {exit_code}[/dim]")
    sys.exit(exit_code)

def run_cd(deploy_cmd):
    show_header()

    if not deploy_cmd:
        console.print("[cyan]━━━ CD WORKFLOW ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/cyan]\n")
        console.print("[red]✖ Deployment command not provided.[/red]\n")
        console.print("Usage:\n[dim]python cli/pipeline/cd.py --cmd \"<deployment-command>\"[/dim]")
        sys.exit(0)
        
    console.print("[cyan]━━━ CD WORKFLOW ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/cyan]\n")
    console.print("Environment     [green]✔ VERIFIED[/green]")
    console.print(f"Command         [dim]{deploy_cmd}[/dim]")
    console.print("Preparation     [green]✔ COMPLETED[/green]")
    console.print("Deployment      [cyan]â— RUNNING[/cyan]\n")

    try:
        run_process = subprocess.Popen(
            deploy_cmd, 
            shell=True, 
            stdout=sys.stdout, 
            stderr=sys.stderr
        )
        run_process.communicate()
        
        if run_process.returncode != 0:
            console.print()
            show_failure(deploy_cmd, run_process.returncode, f"Deployment command exited with code {run_process.returncode}.")

        else:
            console.print("\n[cyan]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/cyan]\n")
            console.print("Deployment Gate [green]✔ PASSED[/green]\n")
            console.print("[cyan]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/cyan]\n")
            console.print("[bold green]✔ CD WORKFLOW PASSED[/bold green]\n")
            console.print("Deployment completed successfully.\n")
            console.print("[dim]Exit code: 0[/dim]")
            
    except Exception as run_err:
        console.print()
        show_failure(deploy_cmd, 1, f"Deployment encountered an error: {run_err}")

if __name__ == "__main__":
    arg_parser = argparse.ArgumentParser(description="Sinful SAST CD Wrapper")
    arg_parser.add_argument("--cmd", type=str, help="Actual deployment command to run (e.g., 'npx vercel --prod')", default="")
    cli_args = arg_parser.parse_args()
    
    run_cd(cli_args.cmd)

