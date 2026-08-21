from cli.views.logger import console

from rich.live import Live
from rich.spinner import Spinner
from rich.table import Table

# Hiển thị biểu tượng tải chờ xử lý
def show_spinner(msg: str, func, *args, **kwargs):
    grid = Table.grid(padding=(0, 1))
    grid.add_row(" ", Spinner("dots12"), f"[bold cyan]{msg}...")
    
    with Live(grid, console=console, refresh_per_second=12.5, transient=True):
        res = func(*args, **kwargs)

    return res
