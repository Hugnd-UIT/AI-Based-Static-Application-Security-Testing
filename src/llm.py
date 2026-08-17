import os
import json
from openai import OpenAI
from main import MODELS

def fetch_llm(prompt: str, model: str = None, is_json: bool = True):
    api_key = os.environ.get("MODEL_API_KEY")
    if not api_key:
        if not is_json:
            return "[!] Model api key is not set", "None"
        raise ValueError("[!] Model api key is not set")

    client = OpenAI(
        api_key=api_key,
        base_url="https://api.xkiro.com/v1"
    )

    fallback = list(MODELS)
    if model:
        if model in fallback:
            fallback.remove(model)
        fallback.insert(0, model)

    error = ""
    for target_model in fallback:
        try:
            kwargs = {
                "model": target_model,
                "messages": [{"role": "system", "content": prompt}],
            }
            if is_json:
                kwargs["response_format"] = {"type": "json_object"}

            response = client.chat.completions.create(**kwargs)
            raw_text = response.choices[0].message.content.strip()
            
            if is_json:
                if raw_text.startswith("```json"):
                    raw_text = raw_text[7:]
                elif raw_text.startswith("```"):
                    raw_text = raw_text[3:]
                if raw_text.endswith("```"):
                    raw_text = raw_text[:-3]
                
                return json.loads(raw_text.strip())
            else:
                return raw_text, target_model

        except Exception as api_err:
            error = str(api_err)
            continue

    if not is_json:
        return f"[!] Error: All fallback models failed. Last error: {error}", "None"
    raise RuntimeError(f"[!] Error: All fallback models failed. Last error: {error}")
