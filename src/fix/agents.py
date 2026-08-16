import os
import json
from google import genai
from google.genai import types
from src.fix.prompts import SYSTEM_PROMPT, USER_PROMPT

def gen_fix(finding_item: dict, source_code: str) -> dict:
    api_key = os.environ.get("MODEL_API_KEY")

    if not api_key:
        raise ValueError("[!] Model api key is not set")

    genai_client = genai.Client(api_key=api_key)

    model_config = types.GenerateContentConfig(
        system_instruction=SYSTEM_PROMPT, temperature=0.0, response_mime_type="application/json"
    )

    prompt_text = USER_PROMPT.format(
        rule=finding_item.get("id", "Unknown Vulnerability"),
        msg=finding_item.get("message", "No description provided."),
        path=finding_item.get("path", "Unknown file"),
        code=source_code,
    )

    try:
        api_resp = genai_client.models.generate_content(
            model="gemini-2.5-flash", contents=prompt_text, config=model_config
        )

        json_data = json.loads(api_resp.text)
        return json_data

    except json.JSONDecodeError:
        raise ValueError("[!] Failed to parse JSON response from LLM")

    except Exception as api_err:
        raise RuntimeError(f"[!] Error calling AI: {str(api_err)}")
