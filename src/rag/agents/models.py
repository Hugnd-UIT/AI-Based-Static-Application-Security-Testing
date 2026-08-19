from src.rag.agents.prompts import PROMPT_TEMPLATE
from src.llm import fetch_llm

def start_rag(cve_context: str, model_name: str = None) -> dict:
    try:
        from cli.views.logger import console
        console.print(f"  ├─ [yellow]Action:[/yellow] [cyan]Analyze CVE Context[/cyan]")
    except ImportError:
        pass
    prompt_text = PROMPT_TEMPLATE.replace("{cve_data}", cve_context)
    return fetch_llm(prompt_text, model_name=model_name, is_json=True)