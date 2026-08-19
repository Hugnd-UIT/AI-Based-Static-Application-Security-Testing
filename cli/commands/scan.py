from cli.views.console import console
from cli.views.viewer import display_diff
import os
from main import start_sast
import src.fix.patch as patcher
import src.fix.agents.models as ai_agents
from cli.views import logger

def execute_scan(target_path: str, auto_fix: bool = False):
    logger.log_info(f"Starting Sinful on {target_path}...")
    logger.blank_line()

    def do_scan():
        model_name = os.environ.get("MODELS")
        return start_sast(target_path, model_name=model_name, auto_fix=auto_fix)

    from cli.views.spinner import show_spinner
    scan_result = show_spinner("Analyzing source code", do_scan)
    logger.blank_line()

    if scan_result.get("status") == "error":
        logger.log_critical(f"Error: {scan_result.get('message')}")
        return

    scan_data = scan_result.get("data", {})
    scan_findings = scan_data.get("findings", [])

    if not scan_findings:
        logger.log_success("No vulnerabilities found! You're clean.")
        return

    if auto_fix:
        logger.blank_line()
        logger.log_info("Auto-fix vulnerabilities...")
        always_allow = False

        def get_user_confirmation(file_name: str) -> str:
            from prompt_toolkit import Application
            from prompt_toolkit.key_binding import KeyBindings
            from prompt_toolkit.layout.containers import Window, HSplit
            from prompt_toolkit.layout.controls import FormattedTextControl
            from prompt_toolkit.layout.layout import Layout
            from prompt_toolkit.styles import Style

            prompt_options = [
                ("y", "Yes (Apply this patch)"),
                ("a", "Yes, Always Allow (Apply all remaining patches automatically)"),
                ("n", "No (Skip this patch)")
            ]
            selected_idx = 0

            key_bindings = KeyBindings()

            @key_bindings.add('up')
            def move_up(event_data):
                nonlocal selected_idx
                selected_idx = (selected_idx - 1) % len(prompt_options)

            @key_bindings.add('down')
            def move_down(event_data):
                nonlocal selected_idx
                selected_idx = (selected_idx + 1) % len(prompt_options)

            @key_bindings.add('enter')
            def confirm_selection(event_data):
                event_data.app.exit(result=prompt_options[selected_idx][0])

            @key_bindings.add('escape')
            @key_bindings.add('c-c')
            def cancel_selection(event_data):
                event_data.app.exit(result="n")

            def format_prompt_text():
                text_lines = [
                    ("class:title", f"Apply this patch to {file_name}?\n")
                ]
                for opt_idx, (opt_val, opt_desc) in enumerate(prompt_options):
                    is_selected = opt_idx == selected_idx
                    pointer_text = "> " if is_selected else "  "
                    line_style = "class:selected" if is_selected else "class:unselected"
                    text_lines.append(("class:pointer" if is_selected else "", pointer_text))
                    text_lines.append((line_style, opt_desc + "\n"))
                return text_lines

            prompt_style = Style.from_dict({
                'title': 'bold #00ffff',
                'pointer': 'bold #5eead4', 
                'selected': 'bold #5eead4',
                'unselected': '#cccccc',
            })

            prompt_layout = Layout(HSplit([Window(content=FormattedTextControl(format_prompt_text), always_hide_cursor=True)]))
            prompt_app = Application(
                layout=prompt_layout, key_bindings=key_bindings, style=prompt_style,
                full_screen=False, erase_when_done=True
            )
            return prompt_app.run()

        for finding_item in scan_findings:
            finding_path = finding_item.get("path")
            if not finding_path:
                continue
                
            fix_data = finding_item.get("fix", {})
            patch_list = fix_data.get("patches", [])
            
            if not patch_list:
                continue

            if "explanation" in fix_data:
                logger.console.print(f"[bold cyan]-+ Fix Strategy:[/bold cyan] {fix_data['explanation']}")
                logger.blank_line()

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

                    display_diff(patch_path, old_code, new_code)
                    logger.blank_line()
                    
                    if always_allow:
                        user_confirm = "y"
                    else:
                        user_confirm = get_user_confirmation(os.path.basename(patch_path))
                        if user_confirm == "a":
                            always_allow = True
                            user_confirm = "y"

                    if user_confirm == "y":
                        if patcher.apply_code_patch(patch_path, old_code, new_code):
                            logger.log_success("Patch applied successfully.")
                        else:
                            logger.log_warning(f"Patch skipped. The original code could not be found.")
                    else:
                        logger.log_warning("Patch rejected by user.")

            except Exception as fix_err:
                logger.log_critical(f"Failed to apply fix for {finding_item.get('id', 'Unknown')}: {fix_err}")

    import json
    from datetime import datetime
    
    report_dir = os.path.join(os.getcwd(), "reports")
    os.makedirs(report_dir, exist_ok=True)
    
    time_stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = os.path.join(report_dir, f"sinful_report_{time_stamp}.json")
    
    try:
        with open(report_path, "w", encoding="utf-8") as file_obj:
            json.dump(scan_result, file_obj, indent=2, ensure_ascii=False)
        logger.blank_line()
        logger.log_success(f"Detailed JSON report saved to: [bold cyan]{report_path}[/bold cyan]")
    except Exception as write_err:
        logger.log_warning(f"Failed to save JSON report: {write_err}")
