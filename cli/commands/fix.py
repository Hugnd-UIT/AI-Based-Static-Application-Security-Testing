from cli.commands.help import display_help
from cli.commands.scan import execute_scan
from cli.views.console import console
import os

# Xử lý các lệnh người dùng nhập vào
def process_command(cmd: str) -> bool:
    raw = cmd.strip()
    if not raw:
        return True

    # Kiểm tra tiền tố lệnh
    if not raw.startswith("/"):
        console.print("  [bold red]o- Invalid command.[/bold red] All commands must start with '/'")
        return True

    low = raw.lower()

    # Thoát ứng dụng
    if low in ["/exit", "/quit"]:
        return False

    # Xóa màn hình
    if low == "/clear":
        os.system("cls" if os.name == "nt" else "clear")
        return True

    # Gọi menu trợ giúp
    if low == "/help":
        display_help()
        return True

    # Quét bảo mật cơ bản
    if low.startswith("/scan"):
        path = raw[5:].strip()
        if path:
            execute_scan(path, fix=False)
        else:
            console.print("  [bold yellow]s Please provide a target path[/bold yellow] Example: [cyan]/scan <path-to-code>[/cyan]")
        return True

    # Quét bảo mật và tự động sửa lỗi
    if low.startswith("/auto-fix"):
        path = raw[9:].strip()
        if path:
            execute_scan(path, fix=True)
        else:
            console.print("  [bold yellow]s Please provide a target path[/bold yellow] Example: [cyan]/auto-fix <path-to-code>[/cyan]")
        return True

    # Lệnh không xác định
    console.print(f"  [bold red]o- Unknown command:[/bold red] {raw.split()[0]}. Type [cyan]/help[/cyan] for a list of commands.")
    return True
