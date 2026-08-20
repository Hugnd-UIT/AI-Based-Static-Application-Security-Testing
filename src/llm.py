import os
import json
from openai import OpenAI
from main import MODELS

def get_keys() -> list:
    keys_str = os.environ.get("AI_KEY", "pk-z28-zmljaw-eW91cnNlbGY-aGFja2Vy")

    return [k.strip() for k in keys_str.split(",") if k.strip()]

def create_client(api_key: str = None) -> OpenAI:
    if not api_key:
        keys = get_keys()
        api_key = keys[0] if keys else "pk-z28-zmljaw-eW91cnNlbGY-aGFja2Vy"
    base_url = "https://ai-based-static-application-security.onrender.com/v1"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}

    return OpenAI(api_key=api_key, base_url=base_url, default_headers=headers)

def get_key(model_name: str) -> str:
    keys = get_keys()

    if not keys:

        return "pk-z28-zmljaw-eW91cnNlbGY-aGFja2Vy"

    try:
        idx = MODELS.index(model_name)

        return keys[idx % len(keys)]

    except ValueError:

        return keys[0]

def fetch_llm(prompt_text: str, model_name: str = None, is_json: bool = True):
    target_model = model_name or MODELS[0]
    api_key = get_key(target_model)
    api_client = create_client(api_key)

    import time
    
    max_retries = 3
    last_error = ""
    
    for attempt in range(max_retries):

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

            if "502" in last_error or "429" in last_error or "connection" in last_error.lower():

                if attempt < max_retries - 1:
                    time.sleep(2 ** attempt)
                    continue
            
            code_str = ""

            if "Error code: " in last_error:
                parts = last_error.split("Error code: ")

                if len(parts) > 1:
                    code_str = parts[1].split()[0].strip("- ")
            
            if code_str:

                if code_str == "403":
                    last_error = "403 Forbidden"

                elif code_str == "401":
                    last_error = "Unauthorized - Check your API Key (401)"

                else:
                    last_error = f"API returned HTTP Error {code_str}"

            elif "<html" in last_error.lower() or "<!doctype" in last_error.lower():
                last_error = "403 Forbidden"

            elif len(last_error) > 200:
                last_error = last_error[:200] + "... [Error Truncated]"
            
            # If not a retryable error or max retries reached

            if not is_json:

                return f"[!] Error: Model failed. Last error: {last_error}", "None"

            raise RuntimeError(f"[!] Error: Model failed. Last error: {last_error}")
            
    if not is_json:

        return f"[!] Error: Model failed. Last error: {last_error}", "None"

    raise RuntimeError(f"[!] Error: Model failed. Last error: {last_error}")

def fetch_tools(
    msg_history: list,
    tool_schemas: list,
    model_name: str = None,
    tool_choice: str = "auto",
):
    target_model = model_name or MODELS[0]
    api_key = get_key(target_model)
    api_client = create_client(api_key)

    import time
    
    max_retries = 3
    last_error = ""
    
    for attempt in range(max_retries):

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

            if "502" in last_error or "429" in last_error or "connection" in last_error.lower():

                if attempt < max_retries - 1:
                    time.sleep(2 ** attempt)
                    continue
            
            code_str = ""

            if "Error code: " in last_error:
                parts = last_error.split("Error code: ")

                if len(parts) > 1:
                    code_str = parts[1].split()[0].strip("- ")
            
            if code_str:

                if code_str == "403":
                    last_error = "403 Forbidden"

                elif code_str == "401":
                    last_error = "Unauthorized - Check your API Key (401)"

                else:
                    last_error = f"API returned HTTP Error {code_str}"

            elif "<html" in last_error.lower() or "<!doctype" in last_error.lower():
                last_error = "403 Forbidden"

            elif len(last_error) > 200:
                last_error = last_error[:200] + "... [Error Truncated]"
            
            raise RuntimeError(f"[!] fetch_tools: Model {target_model} failed. Error: {last_error}")
            
    raise RuntimeError(f"[!] fetch_tools: Model {target_model} failed. Error: {last_error}")
