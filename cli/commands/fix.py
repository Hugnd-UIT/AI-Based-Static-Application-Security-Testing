from cli.commands.help import show_help
from cli.commands.scan import run_scan

def handle_command(user_command: str) -> bool:
    cmd_lower = user_command.strip().lower()

    if cmd_lower in ["exit", "quit", "q", "/exit", "/quit"]:
        return False

    if cmd_lower in ["clear", "/clear"]:
        import os
        os.system("cls" if os.name == "nt" else "clear")
        return True

    if cmd_lower == "/help":
        show_help()
        return True

    should_fix = True
    scan_target = user_command.strip()

    if cmd_lower.startswith("/scan "):
        scan_target = user_command[6:].strip()
        should_fix = False

    elif cmd_lower.startswith("/auto-fix "):
        scan_target = user_command[10:].strip()
        should_fix = True

    if scan_target:
        run_scan(scan_target, fix=should_fix)

    return True
