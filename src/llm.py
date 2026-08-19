import os
import json
from openai import OpenAI
from main import MODELS

def create_client() -> OpenAI:
    api_key = "pk-z28-zmljaw-eW91cnNlbGY-aGFja2Vy"
    base_url = "https://ai-based-static-application-security.onrender.com/v1"
    return OpenAI(api_key=api_key, base_url=base_url)

def fetch_llm(prompt_text: str, model_name: str = None, is_json: bool = True):
    api_client = create_client()

    model_fallback = list(MODELS)
    if model_name:
        if model_name in model_fallback:
            model_fallback.remove(model_name)
        model_fallback.insert(0, model_name)

    last_error = ""
    for target_model in model_fallback:
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
            continue

    if not is_json:
        return f"[!] Error: All fallback models failed. Last error: {last_error}", "None"
    raise RuntimeError(f"[!] Error: All fallback models failed. Last error: {last_error}")


def fetch_llm_tools(
    msg_history: list,
    tool_schemas: list,
    model_name: str = None,
    tool_choice: str = "auto",
):
    api_client = create_client()

    model_fallback = list(MODELS)
    if model_name:
        if model_name in model_fallback:
            model_fallback.remove(model_name)
        model_fallback.insert(0, model_name)

    last_error = ""
    for target_model in model_fallback:
        try:
            api_resp = api_client.chat.completions.create(
                model=target_model,
                messages=msg_history,
                tools=tool_schemas,
                tool_choice=tool_choice,
            )
            return api_resp.choices[0].message, target_model

        except Exception as api_err:
            last_error = str(api_err)
            continue

    raise RuntimeError(f"[!] fetch_llm_tools: All fallback models failed. Last error: {last_error}")
