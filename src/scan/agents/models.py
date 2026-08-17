from src.scan.agents.prompts import PROMPT
from src.llm import fetch_llm

def fetch(finding_item: dict, source_code: str, model: str = None) -> dict:
    prompt = PROMPT.replace("{rule}", str(finding_item.get("id"))) \
                   .replace("{msg}", str(finding_item.get("message"))) \
                   .replace("{path}", str(finding_item.get("path"))) \
                   .replace("{code}", str(source_code))
    return fetch_llm(prompt, model=model, is_json=True)
