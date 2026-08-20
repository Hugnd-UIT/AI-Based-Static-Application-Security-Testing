from cli.commands.help import display_help
from cli.commands.scan import execute_scan
from cli.views.console import console

def process_command(user_command: str) -> bool:
    cmd_raw = user_command.strip()
    if not cmd_raw:
        return True

    if not cmd_raw.startswith("/"):
        console.print("  [bold red]o- Invalid command.[/bold red] All commands must start with '/'")
        return True

    cmd_lower = cmd_raw.lower()

    if cmd_lower in ["/exit", "/quit"]:
        return False

    if cmd_lower == "/clear":
        import os
        os.system("cls" if os.name == "nt" else "clear")
        return True

    if cmd_lower == "/help":
        display_help()
        return True

    if cmd_lower.startswith("/scan"):
        scan_target = cmd_raw[5:].strip()
        if scan_target:
            execute_scan(scan_target, auto_fix=False)
        else:
            console.print("  [bold yellow]s Please provide a target path[/bold yellow] Example: [cyan]/scan <path-to-code>[/cyan]")
        return True

    if cmd_lower.startswith("/auto-fix"):
        scan_target = cmd_raw[9:].strip()
        if scan_target:
            execute_scan(scan_target, auto_fix=True)
        else:
            console.print("  [bold yellow]s Please provide a target path[/bold yellow] Example: [cyan]/auto-fix <path-to-code>[/cyan]")
        return True

    console.print(f"  [bold red]o- Unknown command:[/bold red] {cmd_raw.split()[0]}. Type [cyan]/help[/cyan] for a list of commands.")
    return True
