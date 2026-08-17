from src.audit.agents.prompts import PROMPT
from src.llm import fetch_llm

def fetch(finding_item: dict, source_code: str, cve_context: str = "None", model: str = None):
    prompt = PROMPT.replace("{rule}", str(finding_item.get("id"))) \
                   .replace("{msg}", str(finding_item.get("message"))) \
                   .replace("{path}", str(finding_item.get("path"))) \
                   .replace("{code}", str(source_code)) \
                   .replace("{dflow}", str(finding_item.get("dataflow_trace", "No trace available"))) \
                   .replace("{cve}", str(cve_context))
    return fetch_llm(prompt, model=model, is_json=False)
