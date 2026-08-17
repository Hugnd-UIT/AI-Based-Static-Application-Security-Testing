from cli.views.console import console
from cli.views.viewer import show_diff
import os
from main import run_sast
import src.fix.patch as patcher
import src.fix.agents as ai_agents
from cli.views import logger

def run_scan(target_path: str, fix: bool = False):
    logger.info(f"Starting Sinful scan on {target_path}...")
    logger.blank()

    def execute_scan():
        model = os.environ.get("MODELS")
        return run_sast(target_path, model=model)

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
        logger.info("Initializing AI Auto-Fix...")
        import importlib.util
        from pathlib import Path
        tree_sitter_spec = importlib.util.spec_from_file_location("tree_sitter", Path("src/review/tree-sitter.py").resolve())
        tree_sitter_module = importlib.util.module_from_spec(tree_sitter_spec)
        tree_sitter_spec.loader.exec_module(tree_sitter_module)

        for finding_item in scan_findings:
            finding_path = finding_item.get("path")
            
            if not finding_path or not os.path.exists(finding_path):
                logger.warning(f"File not found for auto-fix: {finding_path}")
                continue

            try:
                start_line = finding_item.get("start", {}).get("line", 1)
                end_line = finding_item.get("end", {}).get("line", 1)
                ast_context = tree_sitter_module.extract_context(finding_path, start_line, end_line, target_dir=target_path)
                
            except Exception as extract_err:
                logger.warning(f"Could not extract context for {finding_path}: {extract_err}")
                continue

            def generate_fix():
                model_to_use = os.environ.get("MODELS", "deepseek/deepseek-v4-flash")
                return ai_agents.gen_fix(finding_item, ast_context, model=model_to_use)

            try:
                logger.info(f"Generating patch for {finding_item.get('id', 'Unknown')}...")
                patch_data = generate_fix()
                patch_list = patch_data.get("patches", [])
                
                if not patch_list:
                    logger.warning("AI did not return valid patch data.")
                    continue

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
                    
                    user_confirm = console.input(f"[bold cyan]Apply this patch to {os.path.basename(patch_path)}? (y/n): [/bold cyan]")

                    if user_confirm.strip().lower() == "y":
                        if patcher.patch(patch_path, old_code, new_code):
                            logger.success("Patch applied successfully.")
                        else:
                            logger.critical(f"Failed to apply patch to {patch_path}.")
                    else:
                        logger.warning("Patch rejected by user.")

            except Exception as fix_err:
                logger.critical(f"Failed to fix {finding_item.get('id', 'Unknown')}: {fix_err}")
