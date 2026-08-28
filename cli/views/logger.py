import time
import sys
from rich.console import Console
from rich.theme import Theme
from rich.text import Text

# Windows encoding
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Theme colors
theme = Theme({
    "dim": "dim #9ca3af",
    "cyan": "bright_cyan",
    "blue": "bright_blue",
    "yellow": "bright_yellow",
    "red": "bright_red",
    "green": "bright_green",
    "magenta": "bright_magenta",
    "bold": "bold",
    "critical": "bold bright_red",
    "high": "bright_red",
    "warning": "bright_yellow",
    "success": "bold bright_green",
    "info": "dim #9ca3af",
    "default": "white",
})

console = Console(theme=theme)
timer = time.time()

# Current time
def _get_timestamp() -> str:
    diff = int(time.time() - timer)
    mins = diff // 60
    secs = diff % 60
    return f"[{mins:02d}:{secs:02d}]"

# Reset time
def reset_timer():
    global timer
    timer = time.time()

# Elapsed time
def get_time() -> float:
    return round(time.time() - timer, 1)

# Print section
def section(title: str):
    text = Text(_get_timestamp(), style="dim")
    text.append(f" ── {title} ", style="cyan bold")
    width = 70
    dashes = width - len(text.plain)

    if dashes > 0:
        text.append("─" * dashes, style="cyan")
    console.print()
    console.print(text)
    console.print()

# Print fatal
def log_critical(msg: str):
    console.print(f"{_get_timestamp()} {msg}", style="critical")

# Print error
def log_high(msg: str):
    console.print(f"{_get_timestamp()} {msg}", style="high")

# Print warn
def log_warning(msg: str):
    console.print(f"{_get_timestamp()} {msg}", style="warning")

# Print success
def log_success(msg: str):
    console.print(f"{_get_timestamp()} {msg}", style="success")

# Print info
def log_info(msg: str):
    console.print(f"{_get_timestamp()} {msg}", style="info")

# Print text
def log_default(msg: str):
    console.print(f"{_get_timestamp()} {msg}", style="default")

# Print blank
def blank_line():
    console.print()

critical = log_critical
high = log_high
warning = log_warning
success = log_success
info = log_info
default = log_default
blank = blank_line
