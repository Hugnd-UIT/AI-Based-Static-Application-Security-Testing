import typer
import os
import sys
from pathlib import Path

# Add path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Set encoding
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

from dotenv import load_dotenv
load_dotenv()

from rich.panel import Panel
from rich.text import Text
from cli.views.console import console

app = typer.Typer(
    name="sinful",
    help="Sinful CLI - Next Gen Zero-Knowledge SAST",
    add_completion=False,
)

# Show header
def display_header():
    wdir = os.getcwd()
    text = Text()

    text.append(">_ Sinful AI", style="bold cyan")
    text.append(" v1.0.0\n\n", style="dim")

    text.append("Welcome back!\n", style="bold cyan")
    
    text.append("directory: ", style="dim")
    text.append(wdir, style="white")

    panel = Panel(text, border_style="dim", padding=(0, 2), expand=False)

    console.print(panel)
    console.print(
        "\n[dim]Tip: For a limited time, Sinful is included in your plan for free - let's secure together![/dim]\n"
    )

@app.callback(invoke_without_command=True)
def start_cli():
    display_header()

    while True:
        try:
            width = console.width
            grey = "\x1b[48;2;55;55;55m"
            reset = "\x1b[0m"

            from prompt_toolkit.application import Application
            from prompt_toolkit.buffer import Buffer
            from prompt_toolkit.layout.containers import Window, VSplit, HSplit
            from prompt_toolkit.layout.controls import BufferControl, FormattedTextControl
            from prompt_toolkit.layout.layout import Layout
            from prompt_toolkit.layout.menus import CompletionsMenu
            from prompt_toolkit.key_binding import KeyBindings
            from prompt_toolkit.styles import Style
            from prompt_toolkit.completion import Completer, Completion
            from prompt_toolkit.output.color_depth import ColorDepth

            # Autocomplete class
            class CommandCompleter(Completer):
                def __init__(self):
                    self.cmds = {
                        '/scan': 'Run a security scan without fixing',
                        '/auto-fix': 'Run a security scan and automatically fix using AI',
                        '/clear': 'Clear terminal',
                        '/help': 'Show list of commands',
                        '/exit': 'Exit terminal',
                    }
                
                def get_completions(self, doc, evt):
                    txt = doc.text_before_cursor

                    if txt.startswith('/'):
                        for key, desc in self.cmds.items():
                            if key.startswith(txt.lower()):
                                yield Completion(
                                    key, 
                                    start_position=-len(txt), 
                                    display=key, 
                                    display_meta=desc
                                )

            buf = Buffer(completer=CommandCompleter(), complete_while_typing=True)

            top = Window(height=1, char=' ', style='bg:#373737')
            pwin = Window(width=4, height=1, content=FormattedTextControl('  > '), style='bg:#373737 fg:ansicyan bold')
            bwin = Window(height=1, content=BufferControl(buffer=buf), style='bg:#373737 fg:#ffffff')
            bot = Window(height=1, char=' ', style='bg:#373737')
            
            root = HSplit([
                top,
                VSplit([pwin, bwin], height=1),
                bot,
                CompletionsMenu(max_height=16, scroll_offset=1)
            ])

            layout = Layout(container=root)

            keys = KeyBindings()
            @keys.add('enter')
            def on_enter(event):
                event.app.exit(result=buf.text)
            @keys.add('c-c')
            def on_cancel(event):
                event.app.exit(result=None)

            style = Style.from_dict({
                'completion-menu': 'bg:default fg:#e5e7eb',
                'completion-menu.completion': 'bg:default fg:#e5e7eb',
                'completion-menu.completion.current': 'bg:#373737 fg:#ffffff',
                'completion-menu.meta.completion': 'bg:default fg:#9ca3af',
                'completion-menu.meta.completion.current': 'bg:#373737 fg:#ffffff',
                'scrollbar.background': 'bg:default fg:default',
                'scrollbar.button': 'bg:default fg:default',
                'scrollbar.arrow': 'bg:default fg:default',
                'status-model': 'fg:ansicyan bold', 
                'status-dot': 'fg:#6b7280',         
                'status-path': 'fg:ansibrightgreen bold',        
            })

            try:
                # Fallback input
                tapp = Application(
                    layout=layout,
                    key_bindings=keys,
                    style=style,
                    color_depth=ColorDepth.TRUE_COLOR,
                    full_screen=False,
                )

                print()
                cmd = tapp.run()

                if cmd is None:
                    break

            except Exception:
                cmd = input(f"\x1b[1A{grey}{' '*width}\n  \x1b[36m\x1b[1m>\x1b[22m\x1b[0m{grey} Enter path or command: \x1b[K\n{' '*width}{reset}\x1b[1A\x1b[25D")

                if not cmd:
                    break

            from cli.commands.fix import process_command

            # Exec cmd
            run = process_command(cmd)

            if not run:
                break

        except KeyboardInterrupt:
            break
        except EOFError:
            break

if __name__ == "__main__":
    start_cli()
