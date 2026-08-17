from src.scan.agents.prompts import PROMPT
from src.llm import fetch_llm

def fetch(finding_item: dict, source_code: str, model: str = None) -> dict:
    prompt = PROMPT.format(
        rule=finding_item.get("id"),
        msg=finding_item.get("message"),
        path=finding_item.get("path"),
        code=source_code
    )
    return fetch_llm(prompt, model=model, is_json=True)
