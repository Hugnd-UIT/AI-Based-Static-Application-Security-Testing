from rich.panel import Panel
from rich.syntax import Syntax
from cli.views.console import console
import difflib

# Print diff
def display_diff(path: str, old: str, new: str):
    lines = list(
        difflib.unified_diff(
            old.splitlines(keepends=True),
            new.splitlines(keepends=True),
            fromfile=f"a/{path}",
            tofile=f"b/{path}",
            n=3,
        )
    )

    text = "".join(lines)

    # If no diff
    if not text:
        console.print("[warning]No changes detected.[/warning]")
        return

    # Output diff
    syn = Syntax(text, "diff", theme="monokai", line_numbers=False)
    panel = Panel(syn, title=f"Patch for [bold]{path}[/bold]", border_style="cyan")

    console.print()
    console.print(panel)
    console.print()
