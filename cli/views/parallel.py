import threading
import concurrent.futures
from textual.app import App, ComposeResult
from textual.containers import Horizontal
from textual.widgets import RichLog, Footer
from cli.views.logger import console as global_console
from rich.text import Text
from rich.console import Console

thread_local = threading.local()
original_print = global_console.print
app_instance = None

class ParallelApp(App):
    BINDINGS = [
        ("ctrl+c", "quit_app", "Quit"),
        ("ctrl+q", "quit_app", "Quit")
    ]
    
    CSS = """
    RichLog {
        width: 1fr;
        height: 100%;
        scrollbar-size: 1 1;
        background: $surface;
    }
    /* Use very pale cyan and pale lime green (xanh la ma nhat) */
    #sca { border: solid #84ffff; border-title-color: #84ffff; border-title-align: center; }
    #sast { border: solid #ccff90; border-title-color: #ccff90; border-title-align: center; }
    """
    
    def __init__(self, sca_func, sast_func):
        super().__init__()
        self.sca_func = sca_func
        self.sast_func = sast_func
        self.sca_res = None
        self.sast_res = None
        self.aborted = True
        
    def compose(self) -> ComposeResult:
        with Horizontal():
            yield RichLog(id="sca", markup=True, wrap=True)
            yield RichLog(id="sast", markup=True, wrap=True)

    def on_mount(self) -> None:
        self.query_one("#sca", RichLog).border_title = "[bold #84ffff]SCA[/bold #84ffff]"
        self.query_one("#sast", RichLog).border_title = "[bold #ccff90]SAST[/bold #ccff90]"
        threading.Thread(target=self.execute_pipelines, daemon=True).start()

    def execute_pipelines(self):
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=2)
        f1 = executor.submit(self.sca_func)
        f2 = executor.submit(self.sast_func)
        self.sca_res = f1.result()
        self.sast_res = f2.result()
        self.aborted = False
        self.call_from_thread(self.exit)

    def action_quit_app(self):
        self.aborted = True
        self.exit()

def patched_print(*args, **kwargs):
    side = getattr(thread_local, "side", None)
    if side not in ("sca", "sast") or app_instance is None:
        original_print(*args, **kwargs)
        return
        
    temp = Console(width=1000, color_system="standard") 
    with temp.capture() as cap:
        temp.print(*args, **kwargs)
    out = cap.get()
    if out.endswith("\n"): 
        out = out[:-1]
    
    try:
        log_widget = app_instance.query_one(f"#{side}", RichLog)
        app_instance.call_from_thread(log_widget.write, Text.from_ansi(out))
    except Exception:
        pass

def run_parallel(sca_func, sast_func):
    global app_instance
    global_console.print = patched_print
    app_instance = ParallelApp(sca_func, sast_func)
    app_instance.run()
    global_console.print = original_print
    
    if getattr(app_instance, "aborted", False):
        import os
        original_print("[bold red]✖ Aborted by user[/bold red]")
        os._exit(1)
        
    return app_instance.sca_res, app_instance.sast_res
