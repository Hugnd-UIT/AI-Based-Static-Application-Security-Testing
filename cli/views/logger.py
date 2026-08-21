import time
import sys
from rich.console import Console
from rich.theme import Theme
from rich.text import Text

# Cấu hình encoding cho Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Giao diện màu sắc cho logger
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

# Lấy nhãn thời gian hiện tại
def _get_timestamp() -> str:
    diff = int(time.time() - timer)
    mins = diff // 60
    secs = diff % 60
    return f"[{mins:02d}:{secs:02d}]"

# Đặt lại thời gian
def reset_timer():
    global timer
    timer = time.time()

# Lấy số giây đã trôi qua
def get_time() -> float:
    return round(time.time() - timer, 1)

# In một phân đoạn mới
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

# In lỗi nghiêm trọng
def log_critical(msg: str):
    console.print(f"{_get_timestamp()} {msg}", style="critical")

# In lỗi cao
def log_high(msg: str):
    console.print(f"{_get_timestamp()} {msg}", style="high")

# In cảnh báo
def log_warning(msg: str):
    console.print(f"{_get_timestamp()} {msg}", style="warning")

# In thành công
def log_success(msg: str):
    console.print(f"{_get_timestamp()} {msg}", style="success")

# In thông tin
def log_info(msg: str):
    console.print(f"{_get_timestamp()} {msg}", style="info")

# In bình thường
def log_default(msg: str):
    console.print(f"{_get_timestamp()} {msg}", style="default")

# In dòng trống
def blank_line():
    console.print()

critical = log_critical
high = log_high
warning = log_warning
success = log_success
info = log_info
default = log_default
blank = blank_line
