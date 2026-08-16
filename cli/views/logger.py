import time
import sys
from rich.console import Console
from rich.theme import Theme
from rich.text import Text

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

logger_theme = Theme({
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

console = Console(theme=logger_theme)
_start_time = time.time()

def _get_timestamp() -> str:
    time_elapsed = int(time.time() - _start_time)
    elapsed_mins = time_elapsed // 60
    elapsed_secs = time_elapsed % 60
    return f"[{elapsed_mins:02d}:{elapsed_secs:02d}]"

def reset_timer():
    global _start_time
    _start_time = time.time()

def get_time_elapsed_secs() -> float:
    return round(time.time() - _start_time, 1)

def section(section_title: str):
    timestamp_text = Text(_get_timestamp(), style="dim")
    timestamp_text.append(f" ── {section_title} ", style="cyan bold")
    term_width = 70
    dashes_needed = term_width - len(timestamp_text.plain)
    if dashes_needed > 0:
        timestamp_text.append("─" * dashes_needed, style="cyan")
    console.print()
    console.print(timestamp_text)
    console.print()

def log_critical(log_message: str):
    console.print(f"{_get_timestamp()} {log_message}", style="critical")

def log_high(log_message: str):
    console.print(f"{_get_timestamp()} {log_message}", style="high")

def log_warning(log_message: str):
    console.print(f"{_get_timestamp()} {log_message}", style="warning")

def log_success(log_message: str):
    console.print(f"{_get_timestamp()} {log_message}", style="success")

def log_info(log_message: str):
    console.print(f"{_get_timestamp()} {log_message}", style="info")

def log_default(log_message: str):
    console.print(f"{_get_timestamp()} {log_message}", style="default")

def blank_line():
    console.print()

critical = log_critical
high = log_high
warning = log_warning
success = log_success
info = log_info
default = log_default
blank = blank_line
