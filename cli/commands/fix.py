from cli.commands.help import display_help
from cli.commands.scan import execute_scan
from cli.views.console import console
import os

# Process input
def process_command(cmd: str) -> bool:
    raw = cmd.strip()
    if not raw:
        return True

    # Check prefix
    if not raw.startswith("/"):
        console.print("  [bold red]o- Invalid command.[/bold red] All commands must start with '/'")
        return True

    low = raw.lower()

    # Exit app
    if low in ["/exit", "/quit"]:
        return False

    # Clear screen
    if low == "/clear":
        os.system("cls" if os.name == "nt" else "clear")
        return True

    # Show help
    if low == "/help":
        display_help()
        return True

    # Base scan
    if low.startswith("/scan"):
        path = raw[5:].strip().strip("\"'")

        if path:
            execute_scan(path, fix=False)
        else:
            console.print("  [bold yellow]s Please provide a target path[/bold yellow] Example: [cyan]/scan <path-to-code>[/cyan]")
        return True

    # Auto fix
    if low.startswith("/auto-fix"):
        path = raw[9:].strip().strip("\"'")

        if path:
            execute_scan(path, fix=True)
        else:
            console.print("  [bold yellow]s Please provide a target path[/bold yellow] Example: [cyan]/auto-fix <path-to-code>[/cyan]")
        return True

    # Unknown cmd
    console.print(f"  [bold red]o- Unknown command:[/bold red] {raw.split()[0]}. Type [cyan]/help[/cyan] for a list of commands.")
    return True
