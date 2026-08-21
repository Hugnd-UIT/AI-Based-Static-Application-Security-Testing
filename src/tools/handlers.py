import json
import logging
from src.llm import fetch_tools
from src.tools import actions

logger = logging.getLogger(__name__)

# Hàm điều phối agent
def run_agent(
    prompt: str,
    message: str,
    schemas: list,
    directory: str,
    module=None,
    model: str = None,
    steps: int = 10,
    agent: str = "AGENT",
) -> dict:
    history = [
        {"role": "system", "content": prompt},
        {"role": "user",   "content": message},
    ]

    for current in range(1, steps + 1):
        try:
            # Gửi công cụ đến AI
            msg, used_model = fetch_tools(
                msg=history,
                schemas=schemas,
                model=model,
                tool="auto",
            )
        
        # Nếu gửi request lỗi thì trả về kết quả cuối cùng
        except RuntimeError as api_err:
            return fallback_verdict(error=str(api_err))
            
        # Nếu nhận response lỗi thì gửi lại request
        if not msg or (not getattr(msg, 'tool_calls', None) and not (getattr(msg, 'content', None) or "").strip()):
            import time
            time.sleep(1)
            continue

        assistant: dict = {"role": "assistant", "content": getattr(msg, 'content', "") or ""}

        if msg.tool_calls:
            # Lấy thông tin về công cụ
            assistant["tool_calls"] = [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {
                        "name": tc.function.name,
                        "arguments": tc.function.arguments,
                    },
                }

                for tc in msg.tool_calls
            ]
        
        # Lưu thông tin về công cụ vào lịch sử
        history.append(assistant)

        # Nếu AI trả về JSON hợp lệ
        if msg.tool_calls:
            verdict_result = None

            for tool_call in msg.tool_calls:
                tool_name = tool_call.function.name

                # Kiểm tra tham số của công cụ
                try:
                    tool_args = json.loads(tool_call.function.arguments)

                except json.JSONDecodeError:
                    tool_args = {}

                try:
                    from cli.views.logger import console
                    
                    # Nếu AI không gọi công cụ nộp kết quả thì hiển thị hành động
                    if tool_name != "submit_verdict":
                        from src.tools.actions import TOOLS
                        
                        if tool_name in TOOLS:
                            display_name = tool_name.replace("_", " ").title()
                        else:
                            display_name = (tool_name[:60] + "...") if len(tool_name) > 60 else tool_name
                        console.print(f"  ├─ [yellow]Action:[/yellow] [cyan]{display_name}[/cyan]")

                except ImportError:
                    pass

                # Nếu AI gọi công cụ nộp kết quả thì ngắt vòng lặp
                if tool_name == "submit_verdict":
                    history.append({
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "content": json.dumps({"status": "verdict_accepted"}),
                    })
                    verdict_result = normalise_verdict(tool_args)
                    continue

                # Nếu AI gọi công cụ thường thì thực thi công cụ
                result = actions.execute_tool(tool_name, tool_args, directory, module)

                # Lưu kết quả vào lịch sử
                history.append({
                    "role": "tool",
                    "call_id": tool_call.id,
                    "content": str(result) if not isinstance(result, str) else result,
                })

            if verdict_result is not None:

                return verdict_result

        # Nếu AI không trả về JSON hợp lệ
        else:
            text = (msg.content or "").strip()
            logger.debug("[%s] Plain text response on step %d", agent, current)

            json = extract_verdict(text)

            if json:
                return normalise_verdict(json)

            if current == steps:
                return fallback_verdict(text=text)

    return fallback_verdict(reason="steps exceeded")

# Hàm chuẩn hóa kết quả
def normalise_verdict(dict: dict) -> dict:
    final = dict(dict)
    final.setdefault("verdict", "UNKNOWN")
    final.setdefault("confidence", 0)
    final.setdefault("severity", "INFO")
    final.setdefault("reason", "")
    return final

# Hàm xử lý kết quả
def fallback_verdict(error: str = "", reason: str = "", text: str = "") -> dict:
    return {
        "verdict": "UNKNOWN",
        "confidence": 0,
        "severity": "INFO",
        "vulns": "N/A",
        "reason": f"Agent loop did not complete. {reason} {error}".strip(),
        "response": text[:500] if text else "",
    }

# Hàm trích xuất kết quả
def extract_verdict(text: str) -> dict | None:
    import re
    fenced = re.search(r"```json\s*(\{.*?\})\s*```", text, re.DOTALL)

    if fenced:

        try:
            return json.loads(fenced.group(1))

        except json.JSONDecodeError:
            pass
    
    bare = re.search(r"\{[^{}]{20,}\}", text, re.DOTALL)

    if bare:

        try:
            return json.loads(bare.group(0))

        except json.JSONDecodeError:
            pass

    return None