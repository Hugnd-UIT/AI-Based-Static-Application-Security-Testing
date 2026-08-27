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
        except RuntimeError as err:
            return fallback_verdict(error=str(err))
            
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
            vresult = None

            for tcall in msg.tool_calls:
                tname = tcall.function.name

                # Kiểm tra tham số của công cụ
                try:
                    targs = json.loads(tcall.function.arguments)

                except json.JSONDecodeError:
                    targs = {}

                try:
                    from cli.views.logger import console
                    
                    # Nếu AI không gọi công cụ nộp kết quả thì hiển thị hành động
                    if tname != "submit_verdict":
                        from src.tools.actions import TOOLS
                        
                        if tname in TOOLS:
                            dname = tname.replace("_", " ").title()
                        else:
                            dname = (tname[:60] + "...") if len(tname) > 60 else tname
                        console.print(f"  ├─ [yellow]Action:[/yellow] [cyan]{dname}[/cyan]")

                except ImportError:
                    pass

                # Nếu AI gọi công cụ nộp kết quả thì ngắt vòng lặp
                if tname == "submit_verdict":
                    history.append({
                        "role": "tool",
                        "tool_call_id": tcall.id,
                        "content": json.dumps({"status": "verdict_accepted"}),
                    })
                    vresult = normalise_verdict(targs)
                    continue

                # Nếu AI gọi công cụ thường thì thực thi công cụ
                result = actions.execute_tool(tname, targs, directory, module)

                # Lưu kết quả vào lịch sử
                history.append({
                    "role": "tool",
                    "tool_call_id": tcall.id,
                    "content": str(result) if not isinstance(result, str) else result,
                })

            if vresult is not None:

                return vresult

        # Nếu AI không trả về JSON hợp lệ
        else:
            text = (msg.content or "").strip()
            logger.debug("[%s] Plain text response on step %d", agent, current)

            jval = extract_verdict(text)

            if jval:
                return normalise_verdict(jval)

            if current == steps:
                return fallback_verdict(text=text)

    return fallback_verdict(reason="steps exceeded")

# Hàm chuẩn hóa kết quả
def normalise_verdict(dval: dict) -> dict:
    final = dict(dval)
    final.setdefault("verdict", "UNKNOWN")
    final.setdefault("confidence", 0)
    final.setdefault("severity", "INFO")
    final.setdefault("reasoning", "")
    return final

# Hàm xử lý kết quả
def fallback_verdict(error: str = "", reason: str = "", text: str = "") -> dict:
    return {
        "verdict": "UNKNOWN",
        "confidence": 0,
        "severity": "INFO",
        "vulns": "N/A",
        "reasoning": f"Agent loop did not complete. {reason} {error}".strip(),
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