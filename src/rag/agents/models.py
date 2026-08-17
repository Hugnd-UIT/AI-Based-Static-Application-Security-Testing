from src.rag.agents.prompts import PROMPT
from src.llm import fetch_llm

def fetch(cve_context: str, model: str = None) -> dict:
    prompt = PROMPT.format(cve_data=cve_context)
    return fetch_llm(prompt, model=model, is_json=True)