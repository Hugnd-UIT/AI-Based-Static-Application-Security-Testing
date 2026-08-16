import os
from google import genai
from google.genai import types
from src.review.prompts import PROMPT

def fetch(finding_item: dict, source_code: str, cve_context: str = "None") -> str:
    api_key = os.environ.get("MODEL_API_KEY")

    if not api_key:
        return "[!] Model api key is not set"

    genai_client = genai.Client(api_key=api_key)
    model_config = types.GenerateContentConfig(
        tools=[{"google_search": {}}],
    )

    prompt_text = PROMPT.format(
        rule=finding_item.get("id"),
        msg=finding_item.get("message"),
        path=finding_item.get("path"),
        code=source_code,
        dflow=str(finding_item.get("dataflow_trace", "No trace available")),
        cve=cve_context,
    )

    try:
        api_resp = genai_client.models.generate_content(
            model="gemini-2.5-flash", contents=prompt_text, config=model_config
        )
        return api_resp.text

    except Exception as api_err:
        return f"[!] Error: {str(api_err)}"
