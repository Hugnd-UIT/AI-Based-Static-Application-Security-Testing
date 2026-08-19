from cli.views.logger import console

from rich.live import Live
from rich.spinner import Spinner
from rich.table import Table

def show_spinner(spin_message: str, target_func, *args, **kwargs):
    grid = Table.grid(padding=(0, 1))
    grid.add_row(" ", Spinner("dots12"), f"[bold cyan]{spin_message}...")
    
    with Live(grid, console=console, refresh_per_second=12.5, transient=True):
        func_result = target_func(*args, **kwargs)
    return func_result
