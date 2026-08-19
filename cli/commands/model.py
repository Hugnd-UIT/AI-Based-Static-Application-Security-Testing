import os
from prompt_toolkit import Application
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout.containers import Window, HSplit
from prompt_toolkit.layout.controls import FormattedTextControl
from prompt_toolkit.layout.layout import Layout
from prompt_toolkit.styles import Style
from cli.views.console import console
from cli.views import logger
from main import MODELS

DESCRIPTIONS = {
    "deepseek/deepseek-v4-flash": "Balanced vulnerability analysis model for everyday security scanning.",
    "mistralai/codestral-2508": "Fast and affordable security model for quick codebase reviews.",
    "qwen/qwen3.8-max": "Frontier model for complex security analysis and zero-day detection.",
    "xiaomi/mimo-v2.5-pro": "Small, fast, and cost-efficient model for simple vulnerability checks.",
    "mistralai/mistral-large-2512": "Large-scale reasoning model for deep SAST and dataflow tracing.",
}

def choose_model(user_command: str):
    cmd_parts = user_command.split(" ", 1)
    
    if len(cmd_parts) > 1 and cmd_parts[1].strip():
        model_input = cmd_parts[1].strip()
        
        if model_input.isdigit():
            idx_val = int(model_input) - 1
            if 0 <= idx_val < len(MODELS):
                model_name = MODELS[idx_val]
            else:
                logger.log_warning(f"Invalid number. Please choose 1-{len(MODELS)}.")
                return
        else:
            model_name = model_input
            
        os.environ["MODELS"] = model_name
        logger.log_success(f"Default AI model set to: [bold cyan]{model_name}[/bold cyan]")
        return

    current_model = os.environ.get("MODELS", MODELS[0])
    
    selected_idx = 0
    if current_model in MODELS:
        selected_idx = MODELS.index(current_model)

    key_bindings = KeyBindings()

    @key_bindings.add('up')
    def move_up(event_data):
        nonlocal selected_idx
        selected_idx = (selected_idx - 1) % len(MODELS)

    @key_bindings.add('down')
    def move_down(event_data):
        nonlocal selected_idx
        selected_idx = (selected_idx + 1) % len(MODELS)

    @key_bindings.add('enter')
    def confirm_selection(event_data):
        event_data.app.exit(result=MODELS[selected_idx])

    @key_bindings.add('escape')
    @key_bindings.add('c-c')
    def cancel_selection(event_data):
        event_data.app.exit(result=None)

    def format_prompt_text():
        text_lines = [
            ("class:title", "\nSelect Model\n"),
            ("class:subtitle", "Access legacy models by passing argument like /model <name>\n\n")
        ]
        
        for list_idx, model_name in enumerate(MODELS):
            is_selected = list_idx == selected_idx
            pointer_text = "> " if is_selected else "  "
            
            status_text = ""
            if model_name == current_model:
                status_text = " (current)"
            elif list_idx == 0:
                status_text = " (default)"
                
            model_desc = DESCRIPTIONS.get(model_name, "")
            
            base_string = f"{list_idx+1}. {model_name}{status_text}"
            padded_base = f"{base_string:<45}"
            
            line_style = "class:selected" if is_selected else "class:unselected"
            if is_selected:
                text_lines.append(("class:pointer", pointer_text))
                text_lines.append((line_style, padded_base))
                text_lines.append(("class:selected", model_desc + "\n"))
            else:
                text_lines.append(("", pointer_text))
                text_lines.append((line_style, padded_base))
                text_lines.append(("class:subtitle", model_desc + "\n"))
                
        text_lines.append(("class:subtitle", "\nPress enter to confirm or esc to go back\n"))
        return text_lines

    prompt_style = Style.from_dict({
        'title': 'bold #ffffff',
        'subtitle': '#888888',
        'pointer': 'bold #5eead4', 
        'selected': 'bold #5eead4',
        'unselected': '#cccccc',
    })

    prompt_layout = Layout(HSplit([Window(content=FormattedTextControl(format_prompt_text), always_hide_cursor=True)]))
    
    prompt_app = Application(
        layout=prompt_layout,
        key_bindings=key_bindings,
        style=prompt_style,
        full_screen=False,
        erase_when_done=True
    )
    
    try:
        import sys
        sys.stdout.write("\x1b[0m\x1b[6A\x1b[J")
        sys.stdout.flush()
        
        chosen_model = prompt_app.run()
        if chosen_model:
            os.environ["MODELS"] = chosen_model
            logger.console.print(f"\n[bold green]✔[/bold green] Switched to [bold cyan]{chosen_model}[/bold cyan]\n")
        else:
            pass
    except Exception as app_err:
        logger.log_warning(f"Interactive UI error: {app_err}")
