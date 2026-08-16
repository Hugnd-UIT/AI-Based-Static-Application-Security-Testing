from cli.views.logger import console

def run_spin(spin_message: str, target_func, *args, **kwargs):
    with console.status(f"[bold cyan]{spin_message}...", spinner="dots12"):
        func_result = target_func(*args, **kwargs)
    return func_result
