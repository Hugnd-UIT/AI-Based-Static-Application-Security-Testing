from src.fix.agents.prompts import PROMPT
from src.llm import fetch_llm

def gen_fix(finding_item: dict, source_code: str, model: str = None) -> dict:
    prompt = PROMPT.format(
        rule=finding_item.get("id", "Unknown Vulnerability"),
        msg=finding_item.get("message", "No description provided."),
        path=finding_item.get("path", "Unknown file"),
        code=source_code,
    )
    return fetch_llm(prompt, model=model, is_json=True)
