import os
import json
from openai import OpenAI
from main import MODELS

# Hàm lấy API key
def get_key(model_name: str = None) -> str:
    # Đọc và tách mảng key từ env
    env = os.environ.get("AI_API_KEY", "pk-z28-zmljaw-eW91cnNlbGY-aGFja2Vy")
    keys = [k.strip() for k in env.split(",") if k.strip()]

    if not keys:
        return "pk-z28-zmljaw-eW91cnNlbGY-aGFja2Vy"

    if model_name:
        try:
            # Chọn key theo model
            idx = MODELS.index(model_name)
            return keys[idx % len(keys)]
        except ValueError:
            return keys[0]

    return keys[0]

# Hàm tạo kết nối đến server
def create_client(api_key: str = None) -> OpenAI:
    if not api_key:
        api_key = get_key()

    # Cấu hình url và headers
    base_url = "https://ai-based-static-application-security.onrender.com/v1"
    default_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}

    return OpenAI(api_key=api_key, base_url=base_url, default_headers=default_headers)

# Hàm gọi đến AI
def fetch_llm(prompt: str, model: str = None, jfmt: bool = True):
    target = model or MODELS[0]
    key = get_key(target)
    client = create_client(key)

    import time

    retries = 3
    errors = ""
    
    for attempt in range(retries):

        try:
            req = {
                "model": target,
                "messages": [{"role": "system", "content": prompt}],
            }

            # Kiểm tra yêu cầu định dạng
            if jfmt:
                req["response_format"] = {"type": "json_object"}

            # Gửi request đến AI
            resp = client.chat.completions.create(**req)
            raw = resp.choices[0].message.content.strip()
            
            # Xử lý json từ AI
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

            # Kiểm tra mã lỗi từ server
            if any(code in errors for code in ("403", "500", "502", "503", "504", "429")) or "<html" in errors.lower() or "<!doctype" in errors.lower() or "connection" in errors.lower() or "timeout" in errors.lower():
            
                # Nếu lỗi thử lại sau 1s, 2s, 4s
                if attempt < retries - 1:
                    time.sleep(2 ** attempt)
                    continue
            
            code = ""

            # Kiểm tra mã lỗi từ AI
            if "Error code: " in errors:
                parts = errors.split("Error code: ")

                if len(parts) > 1:
                    code = parts[1].split()[0].strip("- ")
            
            # Nếu có mã lỗi
            if code:
                
                # Nếu là 403 in ra 403 Forbidden
                if code == "403":
                    errors = "403 Forbidden"

                # Nếu là 401 in ra 401 Unauthorized
                elif code == "401":
                    errors = "401 Unauthorized"

                # Nếu mã lỗi khác in ra HTTP Error + mã lỗi
                else:
                    errors = f"HTTP Error {code}"

            # Nếu có trang html
            elif "<html" in errors.lower() or "<!doctype" in errors.lower():
                errors = "403 Forbidden"

            # Nếu lỗi quá dài
            elif len(errors) > 200:
                errors = errors[:200] + "..."

            if not jfmt:

                return f"[!] Error: Call AI failed. Last error: {errors}", "None"

            raise RuntimeError(f"[!] Error: Call AI failed. Last error: {errors}")

    if not jfmt:

        return f"[!] Error: Call AI failed. Last error: {errors}", "None"

    raise RuntimeError(f"[!] Error: Call AI failed. Last error: {errors}")

# Hàm gửi công cụ đến AI
def fetch_tools(
    msg: list,
    schemas: list,
    model: str = None,
    tool: str = "auto",
):
    target = model or MODELS[0]
    key = get_key(target)
    client = create_client(key)

    import time
    
    retries = 3
    errors = ""
    
    for attempt in range(retries):

        try:
            # Gửi request đến AI
            resp = client.chat.completions.create(
                model=target,
                messages=msg,
                tools=schemas,
                tool_choice=tool,
            )

            # Kiểm tra lựa chọn của AI
            if not getattr(resp, 'choices', None):
                raise RuntimeError(f"Invalid response: {resp}")

            return resp.choices[0].message, target

        except Exception as api_err:
            errors = str(api_err)

            # Kiểm tra mã lỗi từ server
            if any(code in errors for code in ("403", "500", "502", "503", "504", "429")) or "<html" in errors.lower() or "<!doctype" in errors.lower() or "connection" in errors.lower() or "timeout" in errors.lower():
            
                # Nếu lỗi thử lại sau 1s, 2s, 4s
                if attempt < retries - 1:
                    time.sleep(2 ** attempt)
                    continue
            
            code = ""

            # Kiểm tra mã lỗi từ AI
            if "Error code: " in errors:
                parts = errors.split("Error code: ")

                if len(parts) > 1:
                    code = parts[1].split()[0].strip("- ")
            
            # Nếu có mã lỗi
            if code:

                # Nếu là 403 in ra 403 Forbidden
                if code == "403":
                    errors = "403 Forbidden"

                # Nếu là 401 in ra 401 Unauthorized
                elif code == "401":
                    errors = "Unauthorized - Check your API Key (401)"

                # Nếu mã lỗi khác in ra HTTP Error + mã lỗi
                else:
                    errors = f"API returned HTTP Error {code}"

            # Nếu có trang html
            elif "<html" in errors.lower() or "<!doctype" in errors.lower():
                errors = "403 Forbidden"

            # Nếu lỗi quá dài
            elif len(errors) > 200:
                errors = errors[:200] + "... [Error Truncated]"
            
            raise RuntimeError(f"[!] Model {target} failed. Error: {errors}")
            
    raise RuntimeError(f"[!] Model {target} failed. Error: {errors}")