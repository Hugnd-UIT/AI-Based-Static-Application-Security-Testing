from src.fix.agents.prompts import PROMPT
from src.llm import fetch_llm

def gen_fix(finding_item: dict, source_code: str, cve_context: str, model: str = None) -> dict:
    prompt = PROMPT.replace("{rule}", str(finding_item.get("id", "Unknown Vulnerability"))) \
                   .replace("{msg}", str(finding_item.get("message", "No description provided."))) \
                   .replace("{path}", str(finding_item.get("path", "Unknown file"))) \
                   .replace("{code}", str(source_code)) \
                   .replace("{dflow}", str(finding_item.get("dataflow_trace", "No trace available"))) \
                   .replace("{cve}", str(cve_context))
    return fetch_llm(prompt, model=model, is_json=True)
