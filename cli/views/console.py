from rich.console import Console
from rich.theme import Theme

theme = Theme({
    "info": "orange1",
    "warning": "yellow",
    "error": "bold red",
    "success": "bold green",
    "vuln": "bold red on black",
    "highlight": "bold magenta",
})
console = Console(theme=theme)
