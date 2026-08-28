import json
import logging
from src.llm import fetch_tools
from src.tools import actions

logger = logging.getLogger(__name__)

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
            # Send tools to AI
            msg, used_model = fetch_tools(
                msg=history,
                schemas=schemas,
                model=model,
                tool="auto",
            )
        
        # Return final result if request fails
        except RuntimeError as err:
            return fallback_verdict(error=str(err))
            
        # Retry request if response is invalid
        if not msg or (not getattr(msg, 'tool_calls', None) and not (getattr(msg, 'content', None) or "").strip()):
            import time
            time.sleep(1)
            continue

        assistant: dict = {"role": "assistant", "content": getattr(msg, 'content', "") or ""}

        if msg.tool_calls:
            # Extract tool call information
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
        
        # Append tool info to history
        history.append(assistant)

        # If AI returns valid JSON
        if msg.tool_calls:
            vresult = None

            for tcall in msg.tool_calls:
                tname = tcall.function.name

                # Parse tool arguments
                try:
                    targs = json.loads(tcall.function.arguments)

                except json.JSONDecodeError:
                    targs = {}

                try:
                    from cli.views.logger import console
                    
                    # Print action if AI did not submit verdict
                    if tname != "submit_verdict":
                        from src.tools.actions import TOOLS
                        
                        if tname in TOOLS:
                            dname = tname.replace("_", " ").title()
                        else:
                            dname = (tname[:60] + "...") if len(tname) > 60 else tname
                        console.print(f"  ├─ [yellow]Action:[/yellow] [cyan]{dname}[/cyan]")

                except ImportError:
                    pass

                # Break loop if AI submits verdict
                if tname == "submit_verdict":
                    history.append({
                        "role": "tool",
                        "tool_call_id": tcall.id,
                        "content": json.dumps({"status": "verdict_accepted"}),
                    })
                    vresult = normalise_verdict(targs)
                    continue

                # Execute tool if it is a regular tool call
                result = actions.execute_tool(tname, targs, directory, module)

                # Append tool result to history
                history.append({
                    "role": "tool",
                    "tool_call_id": tcall.id,
                    "content": str(result) if not isinstance(result, str) else result,
                })

            if vresult is not None:

                return vresult

        # If AI did not return valid JSON tool calls
        else:
            text = (msg.content or "").strip()
            logger.debug("[%s] Plain text response on step %d", agent, current)

            jval = extract_verdict(text)

            if jval:
                return normalise_verdict(jval)

            if current == steps:
                return fallback_verdict(text=text)

    return fallback_verdict(reason="steps exceeded")

# Normalize verdict function
def normalise_verdict(dval: dict) -> dict:
    final = dict(dval)
    final.setdefault("verdict", "UNKNOWN")
    final.setdefault("confidence", 0)
    final.setdefault("severity", "INFO")
    final.setdefault("reasoning", "")
    return final

# Fallback verdict function
def fallback_verdict(error: str = "", reason: str = "", text: str = "") -> dict:
    return {
        "verdict": "UNKNOWN",
        "confidence": 0,
        "severity": "INFO",
        "vulns": "N/A",
        "reasoning": f"Agent loop did not complete. {reason} {error}".strip(),
        "response": text[:500] if text else "",
    }

# Extract verdict function
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