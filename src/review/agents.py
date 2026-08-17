import os
from openai import OpenAI
from src.review.prompts import PROMPT

MODELS = [
    "deepseek/deepseek-v4-flash",      # DeepSeek V4 Flash 
    "mistralai/codestral-2508",        # Codestral
    "qwen/qwen3.8-max",                # Alibaba Qwen
    "xiaomi/mimo-v2.5-pro",            # Xiaomi MiMo 
    "mistralai/mistral-large-2512"     # Mistral Large
]

def fetch(finding_item: dict, source_code: str, cve_context: str = "None", model: str = None) -> str:
    api_key = os.environ.get("MODEL_API_KEY")

    if not api_key:
        return "[!] Model api key is not set"

    client = OpenAI(
        api_key=api_key,
        base_url="https://api.xkiro.com/v1"
    )

    prompt = PROMPT.format(
        rule=finding_item.get("id"),
        msg=finding_item.get("message"),
        path=finding_item.get("path"),
        code=source_code,
        dflow=str(finding_item.get("dataflow_trace", "No trace available")),
        cve=cve_context,
    )

    fallback = list(MODELS)
    
    if model:
        if model in fallback:
            fallback.remove(model)
        fallback.insert(0, model)

    error = ""
    for target_model in fallback:
        try:
            response = client.chat.completions.create(
                model=target_model,
                messages=[{"role": "user", "content": prompt}]
            )
            return response.choices[0].message.content, target_model
        except Exception as api_err:
            error = str(api_err)
            continue # Auto fallback

    return f"[!] Error: All fallback models failed. Last error: {error}", "None"
