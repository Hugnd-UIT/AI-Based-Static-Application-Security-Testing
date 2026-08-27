from cli.views.console import console
from cli.views.viewer import display_diff
import os
from main import run_scan
import src.fix.patch as patcher
import src.fix.agents.models as ai_agents
from src.tools.actions import resolve_path
from cli.views import logger

# Bắt đầu quét thư mục
def execute_scan(path: str, fix: bool = False):
    logger.log_info(f"Starting Sinful on {path}...")
    logger.blank_line()

    # Không bọc spinner vì tiến trình quét đã tự in ra console
    res = run_scan(path, fix=fix)
    logger.blank_line()

    # Nếu có lỗi
    if res.get("status") == "error":
        logger.log_critical(f"Error: {res.get('message')}")
        return

    # Trích xuất dữ liệu
    data = res.get("data", {})
    finds = data.get("findings", [])
    lost = data.get("unverified", 0)

    # Mất phán quyết thì chưa kết luận được, báo sạch lúc này là bỏ lọt lỗ hổng
    if not finds and lost:
        logger.log_warning(f"Inconclusive: {lost} finding(s) could not be audited, so this is not a clean bill of health.")

    # Nếu không tìm thấy lỗi
    elif not finds:
        logger.log_success("No vulnerabilities found! You're clean.")
        return

    # Nếu chọn tự động sửa lỗi
    if fix:
        logger.blank_line()
        logger.log_info("Auto-fix vulnerabilities...")
        allow = False

        # Hiển thị menu cho người dùng chọn
        def get_confirm(name: str) -> str:
            from prompt_toolkit import Application
            from prompt_toolkit.key_binding import KeyBindings
            from prompt_toolkit.layout.containers import Window, HSplit
            from prompt_toolkit.layout.controls import FormattedTextControl
            from prompt_toolkit.layout.layout import Layout
            from prompt_toolkit.styles import Style

            opts = [
                ("y", "Yes (Apply this patch)"),
                ("a", "Yes, Always Allow (Apply all remaining patches automatically)"),
                ("n", "No (Skip this patch)")
            ]
            idx = 0
            keys = KeyBindings()

            @keys.add('up')
            def move_up(event):
                nonlocal idx
                idx = (idx - 1) % len(opts)

            @keys.add('down')
            def move_down(event):
                nonlocal idx
                idx = (idx + 1) % len(opts)

            @keys.add('enter')
            def confirm_selection(event):
                event.app.exit(result=opts[idx][0])

            @keys.add('escape')
            @keys.add('c-c')
            def cancel_selection(event):
                event.app.exit(result="n")

            # Định dạng UI cho menu chọn
            def format_prompt():
                lines = [("class:title", f"Apply this patch to {name}?\n")]
                for oidx, (val, desc) in enumerate(opts):
                    sel = (oidx == idx)
                    ptr = "> " if sel else "  "
                    style = "class:selected" if sel else "class:unselected"
                    lines.append(("class:pointer" if sel else "", ptr))
                    lines.append((style, desc + "\n"))
                return lines

            pstyle = Style.from_dict({
                'title': 'bold #00ffff',
                'pointer': 'bold #5eead4', 
                'selected': 'bold #5eead4',
                'unselected': '#cccccc',
            })
            layout = Layout(HSplit([Window(content=FormattedTextControl(format_prompt), always_hide_cursor=True)]))
            app = Application(layout=layout, key_bindings=keys, style=pstyle, full_screen=False, erase_when_done=True)
            return app.run()

        # Duyệt qua từng lỗ hổng tìm được
        for find in finds:
            fpath = find.get("path")
            if not fpath:
                continue
            fdata = find.get("fix", {})
            patches = fdata.get("patches", [])
            if not patches:
                continue

            if "explanation" in fdata:
                logger.console.print(f"[bold cyan]-+ Fix Strategy:[/bold cyan] {fdata['explanation']}")
                logger.blank_line()

            try:
                # Duyệt qua các bản vá
                for patch in patches:
                    old = patch.get("old_code", "")
                    new = patch.get("new_code", "")

                    if not old or not new:
                        continue

                    # Chặn AI vá ra ngoài thư mục được quét
                    try:
                        ppath = str(resolve_path(path, patch.get("file_path") or fpath))

                    except ValueError:
                        logger.log_warning(f"Patch rejected, path escapes the target: {patch.get('file_path')}")
                        continue

                    # Nếu AI trả sai đường dẫn thì thử tìm theo tên file
                    if not os.path.exists(ppath):
                        alt = os.path.join(path, os.path.basename(ppath))

                        if os.path.exists(alt):
                            ppath = alt

                    display_diff(ppath, old, new)
                    logger.blank_line()

                    # Kiểm tra xem có áp dụng tự động toàn bộ không
                    if allow:
                        ans = "y"
                    else:
                        ans = get_confirm(os.path.basename(ppath))
                        if ans == "a":
                            allow = True
                            ans = "y"

                    # Áp dụng bản vá
                    if ans == "y":
                        if patcher.apply_patch(ppath, old, new):
                            logger.log_success("Patch applied successfully.")
                        else:
                            logger.log_warning("Patch skipped. The original code could not be found.")
                    else:
                        logger.log_warning("Patch rejected by user.")
            except Exception as err:
                logger.log_critical(f"Failed to apply fix for {find.get('id', 'Unknown')}: {err}")

    # Xuất báo cáo
    from src.report.json import report_json
    from src.report.sarif import report_sarif
    from src.report.html import report_html
    
    rdir = os.path.join(os.getcwd(), "reports")
    try:
        json = report_json(res, rdir)
        sarif = report_sarif(finds, path, rdir)
        html = report_html(finds, path, rdir)
        
        logger.blank_line()
        logger.log_success("Reports saved to:")
        logger.log_success(f"  - JSON:  [bold cyan]{json}[/bold cyan]")
        logger.log_success(f"  - SARIF: [bold cyan]{sarif}[/bold cyan]")
        logger.log_success(f"  - HTML:  [bold cyan]{html}[/bold cyan]")
    except Exception as werr:
        logger.log_warning(f"Failed to save reports: {werr}")