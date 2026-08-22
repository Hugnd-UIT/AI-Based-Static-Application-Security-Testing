import threading
from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.live import Live
from cli.views.logger import console as global_console

thread_local = threading.local()
original_print = global_console.print

class parallel:
    def __init__(self):
        self.layout = Layout()
        self.layout.split_row(
            Layout(name="sca"),
            Layout(name="sast")
        )
        self.sca_items = []
        self.sast_items = []
        self.live = Live(self.layout, console=global_console, refresh_per_second=5, screen=True)
        self._update_panel("sca")
        self._update_panel("sast")
        
    def start(self):
        global_console.print = self.patched_print
        self.live.start()
        
    def stop(self):
        self.live.stop()
        global_console.print = original_print
        global_console.print(self.layout)
        
    def _update_panel(self, side):
        from rich.console import Group
        MAX_ITEMS = 15
        
        if side == "sca":
            visible_items = self.sca_items[-MAX_ITEMS:] if len(self.sca_items) > MAX_ITEMS else self.sca_items
            self.layout["sca"].update(Panel(Group(*visible_items), border_style="cyan"))
        else:
            visible_items = self.sast_items[-MAX_ITEMS:] if len(self.sast_items) > MAX_ITEMS else self.sast_items
            self.layout["sast"].update(Panel(Group(*visible_items), border_style="cyan"))

    def patched_print(self, *args, **kwargs):
        from rich.text import Text
        
        if not args:
            renderable = Text("")
        elif len(args) == 1:
            obj = args[0]
            if isinstance(obj, str):
                style = kwargs.get("style", None)
                try:
                    renderable = Text.from_markup(obj, style=style)
                except Exception:
                    renderable = Text(obj, style=style)
            else:
                renderable = obj
        else:
            text = " ".join(str(a) for a in args)
            style = kwargs.get("style", None)
            try:
                renderable = Text.from_markup(text, style=style)
            except Exception:
                renderable = Text(text, style=style)
                
        side = getattr(thread_local, "side", None)
        if side == "sca":
            self.sca_items.append(renderable)
            self._update_panel("sca")
        elif side == "sast":
            self.sast_items.append(renderable)
            self._update_panel("sast")
        else:
            original_print(*args, **kwargs)
