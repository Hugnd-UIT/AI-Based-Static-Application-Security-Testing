import typer
import os
from dotenv import load_dotenv
load_dotenv()

from rich.panel import Panel
from rich.text import Text
from cli.views.console import console

cli_app = typer.Typer(
    name="sinful",
    help="Sinful CLI - Next Gen Zero-Knowledge SAST",
    add_completion=False,
)

def print_header():
    current_cwd = os.getcwd()
    header_text = Text()

    header_text.append(">_ Sinful AI", style="bold orange1")
    header_text.append(" v1.0.0\n\n", style="dim")

    header_text.append("mode:      ", style="dim")
    header_text.append("auto-fix       ", style="bold white")
    header_text.append("/mode to change\n", style="dim orange1")

    header_text.append("directory: ", style="dim")
    header_text.append(current_cwd, style="white")

    header_panel = Panel(header_text, border_style="dim", padding=(0, 2), expand=False)

    console.print(header_panel)
    console.print(
        "\n[dim]Tip: For a limited time, Sinful Auto-Fix is included in your plan for free — let's secure together.[/dim]\n"
    )

@cli_app.callback(invoke_without_command=True)
def start_cli():
    print_header()

    while True:
        try:
            term_width = console.width
            grey_color = "\x1b[48;2;55;55;55m"
            reset_color = "\x1b[0m"

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

            class CommandCompleter(Completer):
                def __init__(self):
                    self.cli_commands = {
                        '/scan': 'Run a standard security scan without fixing',
                        '/auto-fix': 'Run a scan and automatically fix vulnerabilities using AI',
                        '/model': 'Select or view the default AI model to use',
                        '/clear': 'Clear the terminal screen',
                        '/help': 'Show help message',
                        '/exit': 'Exit the CLI',
                    }
                
                def get_completions(self, document_context, complete_event):
                    text_input = document_context.text_before_cursor
                    if text_input.startswith('/'):
                        for cmd_key, cmd_desc in self.cli_commands.items():
                            if cmd_key.startswith(text_input.lower()):
                                yield Completion(
                                    cmd_key, 
                                    start_position=-len(text_input), 
                                    display=cmd_key, 
                                    display_meta=cmd_desc
                                )

            input_buffer = Buffer(completer=CommandCompleter(), complete_while_typing=True)

            # Setup layout paddings
            top_padding = Window(height=1, char=' ', style='bg:#373737')
            prompt_window = Window(width=4, height=1, content=FormattedTextControl('  › '), style='bg:#373737 fg:#fb923c bold')
            buffer_window = Window(height=1, content=BufferControl(buffer=input_buffer), style='bg:#373737 fg:#ffffff')
            bottom_padding = Window(height=1, char=' ', style='bg:#373737')

            root_container = HSplit([
                top_padding,
                VSplit([prompt_window, buffer_window], height=1),
                bottom_padding,
                CompletionsMenu(max_height=16, scroll_offset=1)
            ])

            app_layout = Layout(container=root_container)

            key_bindings = KeyBindings()
            @key_bindings.add('enter')
            def on_enter(event):
                event.app.exit(result=input_buffer.text)
            @key_bindings.add('c-c')
            def on_cancel(event):
                event.app.exit(result=None)

            prompt_style = Style.from_dict({
                'completion-menu': 'bg:default fg:#e5e7eb',
                'completion-menu.completion': 'bg:default fg:#e5e7eb',
                'completion-menu.completion.current': 'bg:#373737 fg:#ffffff',
                'completion-menu.meta.completion': 'bg:default fg:#9ca3af',
                'completion-menu.meta.completion.current': 'bg:#373737 fg:#ffffff',
                'scrollbar.background': 'bg:default fg:default',
                'scrollbar.button': 'bg:default fg:default',
                'scrollbar.arrow': 'bg:default fg:default',
            })

            toolkit_app = Application(
                layout=app_layout,
                key_bindings=key_bindings,
                style=prompt_style,
                color_depth=ColorDepth.TRUE_COLOR,
                full_screen=False,
            )

            try:
                print()
                target_cmd = toolkit_app.run()
                if target_cmd is None:
                    break
            except Exception:
                target_cmd = input(f"\x1b[1A{grey_color}{' '*term_width}\n  \x1b[38;2;251;146;60m\x1b[1m>\x1b[22m\x1b[0m{grey_color} Enter path or command: \x1b[K\n{' '*term_width}{reset_color}\x1b[1A\x1b[25D")
                if not target_cmd:
                    break

            from cli.commands.fix import handle_command

            should_run = handle_command(target_cmd)

            if not should_run:
                break

        except KeyboardInterrupt:
            break
        except EOFError:
            break

if __name__ == "__main__":
    start_cli()
