from cli.views.console import console
from cli.views.viewer import show_diff
import os
from main import run_sast
import src.fix.patch as patcher
import src.fix.agents.models as ai_agents
from cli.views import logger

def run_scan(target_path: str, fix: bool = False):
    logger.info(f"Starting Sinful on {target_path}...")
    logger.blank()

    def execute_scan():
        model = os.environ.get("MODELS")
        return run_sast(target_path, model=model, fix=fix)

    from cli.views.spinner import run_spin
    scan_result = run_spin("Analyzing source code", execute_scan)
    logger.blank()

    if scan_result.get("status") == "error":
        logger.critical(f"Error: {scan_result.get('message')}")
        return

    scan_data = scan_result.get("data", {})
    scan_findings = scan_data.get("findings", [])

    if not scan_findings:
        logger.success("No vulnerabilities found! You're clean.")
        return

    if fix:
        logger.blank()
        logger.info("Auto-fix vulnerabilities...")
        always_allow = False

        def ask_patch_confirmation(file_name: str) -> str:
            from prompt_toolkit import Application
            from prompt_toolkit.key_binding import KeyBindings
            from prompt_toolkit.layout.containers import Window, HSplit
            from prompt_toolkit.layout.controls import FormattedTextControl
            from prompt_toolkit.layout.layout import Layout
            from prompt_toolkit.styles import Style

            options = [
                ("y", "Yes (Apply this patch)"),
                ("a", "Yes, Always Allow (Apply all remaining patches automatically)"),
                ("n", "No (Skip this patch)")
            ]
            selected_index = 0

            bindings = KeyBindings()

            @bindings.add('up')
            def _(event):
                nonlocal selected_index
                selected_index = (selected_index - 1) % len(options)

            @bindings.add('down')
            def _(event):
                nonlocal selected_index
                selected_index = (selected_index + 1) % len(options)

            @bindings.add('enter')
            def _(event):
                event.app.exit(result=options[selected_index][0])

            @bindings.add('escape')
            @bindings.add('c-c')
            def _(event):
                event.app.exit(result="n")

            def get_prompt_text():
                text = [
                    ("class:title", f"Apply this patch to {file_name}?\n")
                ]
                for i, (val, desc) in enumerate(options):
                    is_selected = i == selected_index
                    pointer = "❯ " if is_selected else "  "
                    line_style = "class:selected" if is_selected else "class:unselected"
                    text.append(("class:pointer" if is_selected else "", pointer))
                    text.append((line_style, desc + "\n"))
                return text

            style = Style.from_dict({
                'title': 'bold #00ffff',
                'pointer': 'bold #5eead4', 
                'selected': 'bold #5eead4',
                'unselected': '#cccccc',
            })

            layout = Layout(HSplit([Window(content=FormattedTextControl(get_prompt_text), always_hide_cursor=True)]))
            app = Application(
                layout=layout, key_bindings=bindings, style=style,
                full_screen=False, erase_when_done=True
            )
            return app.run()

        for finding_item in scan_findings:
            finding_path = finding_item.get("path")
            if not finding_path:
                continue
                
            fix_data = finding_item.get("fix", {})
            patch_list = fix_data.get("patches", [])
            
            if not patch_list:
                continue

            if "explanation" in fix_data:
                logger.console.print(f"[bold cyan]◆ Fix Strategy:[/bold cyan] {fix_data['explanation']}")
                logger.blank()

            try:
                for patch_item in patch_list:
                    patch_path = patch_item.get("file_path", finding_path)
                    old_code = patch_item.get("old_code", "")
                    new_code = patch_item.get("new_code", "")

                    if not old_code or not new_code:
                        continue

                    if not os.path.exists(patch_path):
                        alt_path = os.path.join(target_path, os.path.basename(patch_path))
                        if os.path.exists(alt_path):
                            patch_path = alt_path

                    show_diff(patch_path, old_code, new_code)
                    logger.blank()
                    
                    if always_allow:
                        user_confirm = "y"
                    else:
                        user_confirm = ask_patch_confirmation(os.path.basename(patch_path))
                        if user_confirm == "a":
                            always_allow = True
                            user_confirm = "y"

                    if user_confirm == "y":
                        if patcher.patch(patch_path, old_code, new_code):
                            logger.success("Patch applied successfully.")
                        else:
                            logger.warning(f"Patch skipped. The original code could not be found. It may have already been fixed or modified by a previous patch.")
                    else:
                        logger.warning("Patch rejected by user.")

            except Exception as fix_err:
                logger.critical(f"Failed to apply fix for {finding_item.get('id', 'Unknown')}: {fix_err}")

    import json
    from datetime import datetime
    
    report_dir = os.path.join(os.getcwd(), "reports")
    os.makedirs(report_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = os.path.join(report_dir, f"sinful_report_{timestamp}.json")
    
    try:
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(scan_result, f, indent=2, ensure_ascii=False)
        logger.blank()
        logger.success(f"Detailed JSON report saved to: [bold cyan]{report_path}[/bold cyan]")
    except Exception as e:
        logger.warning(f"Failed to save JSON report: {e}")
