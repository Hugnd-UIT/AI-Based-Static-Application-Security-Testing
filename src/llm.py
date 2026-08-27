import os
import json
import time
import threading
from openai import OpenAI
from src.config import MODELS, BASE_URL, get_keys

_KEY_IDX = 0
_KEY_LOCK = threading.Lock()

_GAP_LOCK = threading.Lock()
_LAST = 0.0

# Khoảng cách tối thiểu giữa hai request, mặc định tắt để không làm chậm khi server không chặn
GAP = float(os.getenv("SINFUL_LLM_GAP") or "0")

# Hàm giữ nhịp gọi AI
def pace():
    global _LAST

    if GAP <= 0:
        return

    with _GAP_LOCK:
        wait = GAP - (time.time() - _LAST)

        if wait > 0:
            time.sleep(wait)

        _LAST = time.time()

# 429 tạm thời cần chờ lâu hơn lỗi khác, nhưng chặn trần để không biến lỗi nhanh thành treo
def wait_time(errors: str, attempt: int) -> float:
    base = 4 if "429" in errors else 2

    return min(30.0, base * (2 ** attempt))

# Hàm lấy API key tiếp theo
def get_next_key() -> str:
    global _KEY_IDX
    keys = get_keys()

    with _KEY_LOCK:
        key = keys[_KEY_IDX % len(keys)]
        _KEY_IDX += 1
    
    return key

# Hàm tạo kết nối đến server
def create_client(api_key: str = None) -> OpenAI:
    if not api_key:
        api_key = get_next_key()

    # Cấu hình url và headers
    default_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}

    return OpenAI(api_key=api_key, base_url=BASE_URL, default_headers=default_headers)

# Hàm kiểm tra lỗi có thể thử lại
def can_retry(errors: str) -> bool:
    low = errors.lower()

    # Hết quota thì thử lại chỉ tốn thời gian
    if is_quota(errors):
        return False

    return (
        any(code in errors for code in ("403", "500", "502", "503", "504", "429"))
        or "<html" in low
        or "<!doctype" in low
        or "connection" in low
        or "timeout" in low
    )

# Hết hạn mức token trong ngày, khác với chặn nhịp tạm thời
def is_quota(errors: str) -> bool:
    low = errors.lower()

    return "quota" in low or "insufficient_quota" in low or "billing" in low

# Hàm chuẩn hóa thông báo lỗi
def norm_error(errors: str) -> str:
    code = ""

    # Kiểm tra mã lỗi từ AI
    if "Error code: " in errors:
        parts = errors.split("Error code: ")

        if len(parts) > 1:
            code = parts[1].split()[0].strip("- ")

    if code == "403":
        return "403 Forbidden"

    if code == "401":
        return "401 Unauthorized - Check your API Key"

    # Hết quota ngày khác hẳn chặn nhịp nên phải nói rõ để người dùng biết đường xử lý
    if is_quota(errors):
        return "429 Daily token quota exhausted - wait for the daily reset or use a paid model"

    if code:
        return f"HTTP Error {code}"

    # Nếu server trả về trang html thay vì json
    if "<html" in errors.lower() or "<!doctype" in errors.lower():
        return "403 Forbidden"

    # Nếu lỗi quá dài
    if len(errors) > 200:
        return errors[:200] + "..."

    return errors

# Hàm gọi đến AI
def fetch_llm(prompt: str, model: str = None, jfmt: bool = True):
    target = model or MODELS[0]
    actual_model = target.split(" ")[0]

    retries = 5
    errors = ""
    
    for attempt in range(retries):
        
        try:
            client = create_client()

            req = {
                "model": actual_model,
                "messages": [{"role": "system", "content": prompt}],
            }

            # Kiểm tra yêu cầu định dạng
            if jfmt:
                req["response_format"] = {"type": "json_object"}

            # Gửi request đến AI
            pace()
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

            # Nếu lỗi tạm thời thì chờ rồi thử lại
            if can_retry(errors) and attempt < retries - 1:
                time.sleep(wait_time(errors, attempt))
                continue

            errors = norm_error(errors)

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

    retries = 5
    errors = ""

    for attempt in range(retries):

        try:
            key = get_next_key()
            client = create_client(key)

            # Gửi request đến AI
            pace()
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

            # Nếu lỗi tạm thời thì chờ rồi thử lại
            if can_retry(errors) and attempt < retries - 1:
                time.sleep(wait_time(errors, attempt))
                continue

            raise RuntimeError(f"[!] Model {target} failed. Error: {norm_error(errors)}")

    raise RuntimeError(f"[!] Model {target} failed. Error: {norm_error(errors)}")