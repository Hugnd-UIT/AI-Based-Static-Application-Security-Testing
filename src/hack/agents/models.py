from src.hack.agents.prompts import PROMPT
from src.llm import fetch_llm

def gen_poc(finding_item: dict, source_code: str, cve_context: str = "None", model: str = None) -> dict:
    prompt = PROMPT.format(
        rule=finding_item.get("id"),
        msg=finding_item.get("message"),
        path=finding_item.get("path"),
        code=source_code,
        dflow=str(finding_item.get("dataflow_trace", "No trace available")),
        cve=cve_context,
    )
    return fetch_llm(prompt, model=model, is_json=True)
