import os
import json
import time
from openai import OpenAI


MODELS = [
    "deepseek/deepseek-v4-pro",
    "qwen/qwen3.8-max:free",
    "qwen/qwen3-coder-plus:free",
    "mistralai/ministral-8b",
    "minimax/minimax-m2.7"
]


def get_key(agent: str = "helper") -> str:
    env = os.environ.get("AI_API_KEY", "")
    keys = [k.strip() for k in env.split(",") if k.strip()]
    if not keys:
        raise ValueError("Missing API key!")
        
    agent = agent.lower()
    if "verifier" in agent or "expander" in agent or "rag" in agent: 
        idx = 0
    elif "scan" in agent: 
        idx = 1
    elif "audit" in agent: 
        idx = 2
    elif "fix" in agent: 
        idx = 3
    else: 
        idx = 4
        
    return keys[idx] if idx < len(keys) else keys[-1]


def get_connect(api_key: str) -> OpenAI:
    base_url = os.environ["AI_URL"]
    default_headers = {"User-Agent": "Mozilla/5.0"}
    return OpenAI(api_key=api_key, base_url=base_url, default_headers=default_headers)


# Check status if retryable
def check_status(errors: str, attempt: int) -> float:
    low = errors.lower()
    if check_quota(errors):
        return 0.0
        
    retryable = (
        any(code in errors for code in ("403", "500", "502", "503", "504", "429"))
        or "<html"      in low
        or "<!doctype"  in low
        or "connection" in low
        or "timeout"    in low
    )
    
    if not retryable:
        return 0.0
        
    base = 4 if "429" in errors else 2
    return min(30.0, base * (2 ** attempt))


# Check quota if exhausted
def check_quota(errors: str) -> bool:
    low = errors.lower()
    return "quota" in low or "insufficient_quota" in low or "billing" in low


# Normalize responses
def normalize_msg(errors: str) -> str:
    code = ""
    if "Error code: " in errors:
        parts = errors.split("Error code: ")
        if len(parts) > 1:
            code = parts[1].split()[0].strip("- ")

    if code == "403": 
        return "403 Forbidden"
    
    if code == "401": 
        return "401 Unauthorized"

    if check_quota(errors):
        return "429 Quota exhausted"

    if code:
        return f"HTTP Error {code}"

    if "<html" in errors.lower() or "<!doctype" in errors.lower():
        return "403 Forbidden"

    if len(errors) > 200:
        return errors[:200] + "..."

    return errors


# Call LLM agent without tools
def fetch_llm(prompt: str, model: str = None, jfmt: bool = True, agent: str = "helper"):
    primary = model or os.environ["AI_MODEL"]
    secondary = [primary] + MODELS
    errors = ""

    for target in secondary:
        target = target.split(" ")[0]
        retries = 3 if target == primary else 1
        
        for attempt in range(retries):
            try:
                client = get_connect(get_key(agent))

                req = {
                    "model":    target,
                    "messages": [{"role": "system", "content": prompt}],
                }
                
                if jfmt:
                    req["response_format"] = {"type": "json_object"}

                res = client.chat.completions.create(**req)
                raw  = res.choices[0].message.content.strip()

                if jfmt:
                    if raw.startswith("```json"): 
                        raw = raw[7:]
                    elif raw.startswith("```"):   
                        raw = raw[3:]
                    
                    if raw.endswith("```"):       
                        raw = raw[:-3]
                    
                    return json.loads(raw.strip())
                else:
                    return raw, target

            except Exception as api_err:
                errors = str(api_err)

                wait = check_status(errors, attempt)
                if wait > 0 and attempt < retries - 1:
                    time.sleep(wait)
                    continue
                
                errors = normalize_msg(errors)
                break
                
    if not jfmt:
        return f"[!] Error: Call AI failed. Last error: {errors}", "None"

    raise RuntimeError(f"[!] Error: Call AI failed. Last error: {errors}")


# Call LLM agent with tools
def fetch_tools(msg: list, schemas: list, model: str = None, tool: str = "auto", agent: str = "helper"):
    primary = model or os.environ["AI_MODEL"]
    secondary = [primary] + MODELS
    errors = ""

    for target in secondary:
        retries = 3 if target == primary else 1
        
        for attempt in range(retries):
            try:
                client = get_connect(get_key(agent))

                res = client.chat.completions.create(
                    model=target,
                    messages=msg,
                    tools=schemas,
                    tool_choice=tool,
                )

                if not getattr(res, "choices", None):
                    raise RuntimeError(f"Invalid response: {res}")

                return res.choices[0].message, target

            except Exception as api_err:
                errors = str(api_err)

                wait_sec = check_status(errors, attempt)
                if wait_sec > 0 and attempt < retries - 1:
                    time.sleep(wait_sec)
                    continue
                break

    raise RuntimeError(f"[!] Error: Call AI failed. Last error: {normalize_msg(errors)}")