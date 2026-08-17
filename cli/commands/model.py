import os
from prompt_toolkit import Application
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout.containers import Window, HSplit
from prompt_toolkit.layout.controls import FormattedTextControl
from prompt_toolkit.layout.layout import Layout
from prompt_toolkit.styles import Style
from cli.views.console import console
from cli.views import logger
from src.review.agents import MODELS  

DESCRIPTIONS = {
    "deepseek/deepseek-v4-flash": "Balanced vulnerability analysis model for everyday security scanning.",
    "mistralai/codestral-2508": "Fast and affordable security model for quick codebase reviews.",
    "qwen/qwen3.8-max": "Frontier model for complex security analysis and zero-day detection.",
    "xiaomi/mimo-v2.5-pro": "Small, fast, and cost-efficient model for simple vulnerability checks.",
    "mistralai/mistral-large-2512": "Large-scale reasoning model for deep SAST and dataflow tracing.",
}

def set_model(user_command: str):
    cmd_parts = user_command.split(" ", 1)
    
    # If the user explicitly passes an argument, handle it silently
    if len(cmd_parts) > 1 and cmd_parts[1].strip():
        model_input = cmd_parts[1].strip()
        
        if model_input.isdigit():
            idx = int(model_input) - 1
            if 0 <= idx < len(MODELS):
                model_name = MODELS[idx]
            else:
                logger.warning(f"Invalid number. Please choose 1-{len(MODELS)}.")
                return
        else:
            model_name = model_input
            
        os.environ["MODELS"] = model_name
        logger.success(f"Default AI model set to: [bold cyan]{model_name}[/bold cyan]")
        return

    # Interactive UI for when user just types /model
    current_model = os.environ.get("MODELS", MODELS[0])
    
    selected_index = 0
    if current_model in MODELS:
        selected_index = MODELS.index(current_model)

    bindings = KeyBindings()

    @bindings.add('up')
    def _(event):
        nonlocal selected_index
        selected_index = (selected_index - 1) % len(MODELS)

    @bindings.add('down')
    def _(event):
        nonlocal selected_index
        selected_index = (selected_index + 1) % len(MODELS)

    @bindings.add('enter')
    def _(event):
        event.app.exit(result=MODELS[selected_index])

    @bindings.add('escape')
    @bindings.add('c-c')
    def _(event):
        event.app.exit(result=None)

    def get_prompt_text():
        text = [
            ("class:title", "\nSelect Model\n"),
            ("class:subtitle", "Access legacy models by passing argument like /model <name>\n\n")
        ]
        
        for i, model in enumerate(MODELS):
            is_selected = i == selected_index
            pointer = "> " if is_selected else "  "
            
            status = ""
            if model == current_model:
                status = " (current)"
            elif i == 0:
                status = " (default)"
                
            desc = DESCRIPTIONS.get(model, "")
            
            base_str = f"{i+1}. {model}{status}"
            padded_base = f"{base_str:<45}"
            
            line_style = "class:selected" if is_selected else "class:unselected"
            if is_selected:
                text.append(("class:pointer", pointer))
                text.append((line_style, padded_base))
                text.append(("class:selected", desc + "\n"))
            else:
                text.append(("", pointer))
                text.append((line_style, padded_base))
                text.append(("class:subtitle", desc + "\n"))
                
        text.append(("class:subtitle", "\nPress enter to confirm or esc to go back\n"))
        return text

    style = Style.from_dict({
        'title': 'bold #ffffff',
        'subtitle': '#888888',
        'pointer': 'bold #5eead4', 
        'selected': 'bold #5eead4',
        'unselected': '#cccccc',
    })

    layout = Layout(HSplit([Window(content=FormattedTextControl(get_prompt_text), always_hide_cursor=True)]))
    
    app = Application(
        layout=layout,
        key_bindings=bindings,
        style=style,
        full_screen=False,
        erase_when_done=True
    )
    
    try:
        import sys
        sys.stdout.write("\x1b[0m\x1b[6A\x1b[J")
        sys.stdout.flush()
        
        chosen_model = app.run()
        if chosen_model:
            os.environ["MODELS"] = chosen_model
            logger.console.print(f"\n[bold green]✔[/bold green] Switched to [bold cyan]{chosen_model}[/bold cyan]\n")
        else:
            pass
    except Exception as e:
        logger.warning(f"Interactive UI error: {e}")
