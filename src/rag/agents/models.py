from src.rag.agents.prompts import PROMPT_TEMPLATE
from src.llm import fetch_llm

def start_rag(cve_context: str, model_name: str = None) -> dict:

    prompt_text = PROMPT_TEMPLATE.replace("{cve_data}", cve_context)

    return fetch_llm(prompt_text, model_name=model_name, is_json=True)