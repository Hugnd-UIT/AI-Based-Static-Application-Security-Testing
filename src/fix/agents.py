import os
import json

from src.fix.prompts import SYSTEM_PROMPT, USER_PROMPT

def gen_fix(finding_item: dict, source_code: str, model: str = "deepseek/deepseek-v4-flash") -> dict:
    from openai import OpenAI
    api_key = os.environ.get("MODEL_API_KEY")

    if not api_key:
        raise ValueError("[!] Model api key is not set")

    client = OpenAI(
        api_key=api_key,
        base_url="https://api.xkiro.com/v1"
    )

    prompt_text = USER_PROMPT.format(
        rule=finding_item.get("id", "Unknown Vulnerability"),
        msg=finding_item.get("message", "No description provided."),
        path=finding_item.get("path", "Unknown file"),
        code=source_code,
    )

    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt_text}
            ],
            response_format={"type": "json_object"}
        )

        raw_text = response.choices[0].message.content.strip()
        if raw_text.startswith("```json"):
            raw_text = raw_text[7:]
        if raw_text.startswith("```"):
            raw_text = raw_text[3:]
        if raw_text.endswith("```"):
            raw_text = raw_text[:-3]

        json_data = json.loads(raw_text.strip())
        return json_data

    except json.JSONDecodeError:
        raise ValueError("[!] Failed to parse JSON response from LLM")

    except Exception as api_err:
        raise RuntimeError(f"[!] Error calling AI: {str(api_err)}")
