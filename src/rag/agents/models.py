import os
import json
from src.rag.agents.prompts import PROMPT

def fetch(cve_context: str, model: str = None) -> dict:
    from openai import OpenAI
    api_key = os.environ.get("MODEL_API_KEY")

    if not api_key:
        raise ValueError("[!] Model api key is not set")

    client = OpenAI(
        api_key=api_key,
        base_url="https://api.xkiro.com/v1"
    )

    prompt = PROMPT.format(cve_data=cve_context)

    from main import MODELS
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
                messages=[
                    {"role": "system", "content": prompt}
                ],
                response_format={"type": "json_object"}
            )
            
            raw_text = response.choices[0].message.content.strip()
            
            if raw_text.startswith("```json"):
                raw_text = raw_text[7:]
            elif raw_text.startswith("```"):
                raw_text = raw_text[3:]
            if raw_text.endswith("```"):
                raw_text = raw_text[:-3]

            json_data = json.loads(raw_text.strip())
            return json_data

        except Exception as api_err:
            error = str(api_err)
            continue

    raise RuntimeError(f"[!] Error: All fallback models failed. Last error: {error}")