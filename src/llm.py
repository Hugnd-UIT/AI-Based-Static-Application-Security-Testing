import os
import json
from openai import OpenAI
from main import MODELS

def get_api_keys() -> list:
    keys_str = os.environ.get("AI_API_KEY", "pk-z28-zmljaw-eW91cnNlbGY-aGFja2Vy")
    return [k.strip() for k in keys_str.split(",") if k.strip()]

def create_client(api_key: str = None) -> OpenAI:
    if not api_key:
        keys = get_api_keys()
        api_key = keys[0] if keys else "pk-z28-zmljaw-eW91cnNlbGY-aGFja2Vy"
    base_url = "https://ai-based-static-application-security.onrender.com/v1"
    return OpenAI(api_key=api_key, base_url=base_url)

def get_key_for_model(model_name: str) -> str:
    keys = get_api_keys()
    if not keys:
        return "pk-z28-zmljaw-eW91cnNlbGY-aGFja2Vy"
    try:
        idx = MODELS.index(model_name)
        return keys[idx % len(keys)]
    except ValueError:
        return keys[0]

def fetch_llm(prompt_text: str, model_name: str = None, is_json: bool = True):
    target_model = model_name or MODELS[0]
    api_key = get_key_for_model(target_model)
    api_client = create_client(api_key)

    try:
        req_kwargs = {
            "model": target_model,
            "messages": [{"role": "system", "content": prompt_text}],
        }
        if is_json:
            req_kwargs["response_format"] = {"type": "json_object"}

        api_resp = api_client.chat.completions.create(**req_kwargs)
        raw_text = api_resp.choices[0].message.content.strip()
        
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
        last_error = str(api_err)
        if not is_json:
            return f"[!] Error: Model failed. Last error: {last_error}", "None"
        raise RuntimeError(f"[!] Error: Model failed. Last error: {last_error}")

def fetch_llm_tools(
    msg_history: list,
    tool_schemas: list,
    model_name: str = None,
    tool_choice: str = "auto",
):
    target_model = model_name or MODELS[0]
    api_key = get_key_for_model(target_model)
    api_client = create_client(api_key)

    try:
        api_resp = api_client.chat.completions.create(
            model=target_model,
            messages=msg_history,
            tools=tool_schemas,
            tool_choice=tool_choice,
        )
        return api_resp.choices[0].message, target_model

    except Exception as api_err:
        raise RuntimeError(f"[!] fetch_llm_tools: Model {target_model} failed. Error: {api_err}")
