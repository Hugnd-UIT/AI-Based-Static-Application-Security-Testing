import os
import json
import time
from openai import OpenAI

def get_keys() -> list:
    env = os.environ.get("AI_API_KEY", "")
    keys = [k.strip() for k in env.split(",") if k.strip()]
    if not keys:
        raise ValueError("Missing AI_API_KEY in .env!")
    return keys

def _key_at(idx: int) -> str:
    keys = get_keys()
    return keys[idx] if idx < len(keys) else keys[-1]

def get_key_rag()    -> str: return _key_at(0)
def get_key_scan()   -> str: return _key_at(1)
def get_key_audit()  -> str: return _key_at(2)
def get_key_fix()    -> str: return _key_at(3)
def get_key_helper() -> str: return _key_at(4)

# 429 needs longer wait than other errors, but cap at 30s to avoid hanging forever
def wait_time(errors: str, attempt: int) -> float:
    base = 4 if "429" in errors else 2
    return min(30.0, base * (2 ** attempt))

# Each AI role uses its own dedicated key, determined by the model name passed in
def get_key_for_model(model_name: str) -> str:
    name = model_name.lower()
    if "rag"   in name: return get_key_rag()
    if "scan"  in name: return get_key_scan()
    if "audit" in name: return get_key_audit()
    if "fix"   in name: return get_key_fix()
    return get_key_helper()

# Create an OpenAI-compatible client pointed at xkiro
def create_client(api_key: str) -> OpenAI:
    base_url = os.environ["AI_URL"]
    default_headers = {"User-Agent": "Mozilla/5.0"}
    return OpenAI(api_key=api_key, base_url=base_url, default_headers=default_headers)

# Check if the error is worth retrying
def can_retry(errors: str) -> bool:
    low = errors.lower()
    if is_quota(errors):
        return False
    return (
        any(code in errors for code in ("403", "500", "502", "503", "504", "429"))
        or "<html"      in low
        or "<!doctype"  in low
        or "connection" in low
        or "timeout"    in low
    )

# Quota exhaustion is permanent (for today) — no point retrying
def is_quota(errors: str) -> bool:
    low = errors.lower()
    return "quota" in low or "insufficient_quota" in low or "billing" in low

# Normalize raw error strings into a short readable message
def norm_error(errors: str) -> str:
    code = ""
    if "Error code: " in errors:
        parts = errors.split("Error code: ")
        if len(parts) > 1:
            code = parts[1].split()[0].strip("- ")

    if code == "403": return "403 Forbidden"
    if code == "401": return "401 Unauthorized - Check your API Key"

    if is_quota(errors):
        return "429 Daily token quota exhausted"

    if code:
        return f"HTTP Error {code}"

    if "<html" in errors.lower() or "<!doctype" in errors.lower():
        return "403 Forbidden"

    if len(errors) > 200:
        return errors[:200] + "..."

    return errors

# Send a plain prompt to the AI and return JSON or raw text
def fetch_llm(prompt: str, model: str = None, jfmt: bool = True):
    primary = model or os.environ["AI_MODEL"]
    
    # 5 free xkiro fallback models
    fallbacks = [
        "google/gemini-1.5-flash",
        "meta-llama/llama-3-8b-instruct",
        "mistralai/mistral-7b-instruct-v0.3",
        "qwen/qwen-2-7b-instruct",
        "microsoft/phi-3-mini-128k-instruct"
    ]
    
    models_to_try = [primary] + fallbacks
    errors = ""

    for target in models_to_try:
        actual_model = target.split(" ")[0]
        retries = 3 if target == primary else 1
        
        for attempt in range(retries):
            try:
                client = create_client(get_key_for_model(target))

                req = {
                    "model":    actual_model,
                    "messages": [{"role": "system", "content": prompt}],
                }
                if jfmt:
                    req["response_format"] = {"type": "json_object"}

                resp = client.chat.completions.create(**req)
                raw  = resp.choices[0].message.content.strip()

                if jfmt:
                    if raw.startswith("```json"): raw = raw[7:]
                    elif raw.startswith("```"):   raw = raw[3:]
                    if raw.endswith("```"):       raw = raw[:-3]
                    return json.loads(raw.strip())
                else:
                    return raw, target

            except Exception as api_err:
                errors = str(api_err)

                if can_retry(errors) and attempt < retries - 1:
                    time.sleep(wait_time(errors, attempt))
                    continue
                
                errors = norm_error(errors)
                # Break out of inner retry loop to try next fallback model
                break
                
    if not jfmt:
        return f"[!] Error: Call AI failed. Last error: {errors}", "None"

    raise RuntimeError(f"[!] Error: Call AI failed. Last error: {errors}")

# Send a tool-calling request to the AI
def fetch_tools(msg: list, schemas: list, model: str = None, tool: str = "auto"):
    primary = model or os.environ["AI_MODEL"]
    
    fallbacks = [
        "google/gemini-1.5-flash",
        "meta-llama/llama-3-8b-instruct",
        "mistralai/mistral-7b-instruct-v0.3",
        "qwen/qwen-2-7b-instruct",
        "microsoft/phi-3-mini-128k-instruct"
    ]
    
    models_to_try = [primary] + fallbacks
    errors = ""

    for target in models_to_try:
        retries = 3 if target == primary else 1
        
        for attempt in range(retries):
            try:
                client = create_client(get_key_for_model(target))

                resp = client.chat.completions.create(
                    model=target,
                    messages=msg,
                    tools=schemas,
                    tool_choice=tool,
                )

                if not getattr(resp, "choices", None):
                    raise RuntimeError(f"Invalid response: {resp}")

                return resp.choices[0].message, target

            except Exception as api_err:
                errors = str(api_err)

                if can_retry(errors) and attempt < retries - 1:
                    time.sleep(wait_time(errors, attempt))
                    continue
                
                # Break out of inner retry loop to try next fallback model
                break

    raise RuntimeError(f"[!] All models failed. Last Error: {norm_error(errors)}")