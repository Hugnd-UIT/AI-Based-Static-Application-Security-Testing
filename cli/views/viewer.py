from rich.panel import Panel
from rich.syntax import Syntax
from cli.views.console import console
import difflib

def display_diff(target_path: str, old_code: str, new_code: str):
    diff_lines = list(
        difflib.unified_diff(
            old_code.splitlines(keepends=True),
            new_code.splitlines(keepends=True),
            fromfile=f"a/{target_path}",
            tofile=f"b/{target_path}",
            n=3,
        )
    )

    diff_text = "".join(diff_lines)

    if not diff_text:
        console.print("[warning]No changes detected.[/warning]")
        return

    rich_syntax = Syntax(diff_text, "diff", theme="monokai", line_numbers=False)
    diff_panel = Panel(rich_syntax, title=f"Patch for [bold]{target_path}[/bold]", border_style="cyan")

    console.print()
    console.print(diff_panel)
    console.print()
