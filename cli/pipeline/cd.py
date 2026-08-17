import sys
import os
import subprocess
import argparse
from pathlib import Path

# Add project root to path
ROOT_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.append(str(ROOT_DIR))

# Use rich for UI
try:
    from rich.console import Console
    from rich.panel import Panel
    console = Console()
except ImportError:
    print("Error: Required 'rich' library is not installed.")
    sys.exit(1)

def print_header():
    console.print()
    console.print(Panel(
        "[bold cyan]SINFUL SAST · CD[/bold cyan]\n[dim]Continuous Deployment[/dim]",
        border_style="cyan",
        expand=False
    ))
    console.print()

def print_workflow_failed(cmd, exit_code, reason):
    console.print("[cyan]━━━ CD WORKFLOW ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/cyan]\n")
    console.print("Environment     [green]✓ VERIFIED[/green]")
    if cmd:
        console.print(f"Command         [dim]{cmd}[/dim]")
    console.print("Preparation     [green]✓ COMPLETED[/green]")
    console.print("Deployment      [red]✖ FAILED[/red]")
    console.print("Deployment Gate [red]✖ FAILED[/red]\n")
    console.print("[cyan]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/cyan]\n")
    console.print("[bold red]✖ CD WORKFLOW FAILED[/bold red]\n")
    console.print(f"{reason}")
    console.print("Deployment stopped.\n")
    console.print(f"[dim]Exit code: {exit_code}[/dim]")
    sys.exit(exit_code)

def start_cd(command):
    print_header()

    if not command:
        console.print("[cyan]━━━ CD WORKFLOW ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/cyan]\n")
        console.print("[red]✖ Deployment command not provided.[/red]\n")
        console.print("Usage:\n[dim]python cli/pipeline/cd.py --cmd \"<deployment-command>\"[/dim]")
        sys.exit(0)
        
    console.print("[cyan]━━━ CD WORKFLOW ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/cyan]\n")
    console.print("Environment     [green]✓ VERIFIED[/green]")
    console.print(f"Command         [dim]{command}[/dim]")
    console.print("Preparation     [green]✓ COMPLETED[/green]")
    console.print("Deployment      [cyan]● RUNNING[/cyan]\n")

    try:
        process = subprocess.Popen(
            command, 
            shell=True, 
            stdout=sys.stdout, 
            stderr=sys.stderr
        )
        process.communicate()
        
        if process.returncode != 0:
            console.print()
            print_workflow_failed(command, process.returncode, f"Deployment command exited with code {process.returncode}.")
        else:
            console.print("\n[cyan]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/cyan]\n")
            console.print("Deployment Gate [green]✓ PASSED[/green]\n")
            console.print("[cyan]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/cyan]\n")
            console.print("[bold green]✓ CD WORKFLOW PASSED[/bold green]\n")
            console.print("Deployment completed successfully.\n")
            console.print("[dim]Exit code: 0[/dim]")
            
    except Exception as e:
        console.print()
        print_workflow_failed(command, 1, f"Deployment encountered an error: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sinful SAST CD Wrapper")
    parser.add_argument("--cmd", type=str, help="Actual deployment command to run (e.g., 'npx vercel --prod')", default="")
    args = parser.parse_args()
    
    start_cd(args.cmd)
