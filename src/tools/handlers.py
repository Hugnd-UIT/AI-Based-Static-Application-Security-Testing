import json
import logging
from src.llm import fetch_llm_tools
from src.tools import actions

logger = logging.getLogger(__name__)

def run_agent(
    system_prompt: str,
    initial_message: str,
    tool_schemas: list,
    target_dir: str,
    ts_module=None,
    model_name: str = None,
    max_steps: int = 10,
    agent_name: str = "AGENT",
) -> dict:
    msg_history = [
        {"role": "system", "content": system_prompt},
        {"role": "user",   "content": initial_message},
    ]

    for curr_step in range(1, max_steps + 1):
        logger.debug("[%s] Step %d/%d", agent_name, curr_step, max_steps)

        try:
            api_msg, used_model = fetch_llm_tools(
                msg_history=msg_history,
                tool_schemas=tool_schemas,
                model_name=model_name,
                tool_choice="auto",
            )
        except RuntimeError as api_err:
            logger.warning("[%s] API error on step %d: %s", agent_name, curr_step, api_err)
            return fallback_verdict(error_msg=str(api_err))

        assistant_msg: dict = {"role": "assistant", "content": api_msg.content or ""}
        if api_msg.tool_calls:
            assistant_msg["tool_calls"] = [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {
                        "name": tc.function.name,
                        "arguments": tc.function.arguments,
                    },
                }
                for tc in api_msg.tool_calls
            ]
        msg_history.append(assistant_msg)

        if api_msg.tool_calls:
            verdict_result = None
            for tool_call in api_msg.tool_calls:
                tool_name = tool_call.function.name
                try:
                    tool_args = json.loads(tool_call.function.arguments)
                except json.JSONDecodeError:
                    tool_args = {}

                logger.debug("[%s] Tool: %s(%s)", agent_name, tool_name, list(tool_args))

                try:
                    from cli.views.logger import console
                    if tool_name != "submit_verdict":
                        display_name = tool_name.replace("_", " ").title()
                        console.print(f"  ├─ [yellow]Action:[/yellow] [cyan]{display_name}[/cyan]")
                except ImportError:
                    pass

                if tool_name == "submit_verdict":
                    msg_history.append({
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "content": json.dumps({"status": "verdict_accepted"}),
                    })
                    logger.debug("[%s] submit_verdict received stopping.", agent_name)
                    verdict_result = normalise_verdict(tool_args)
                    continue

                exec_result = actions.execute_tool(tool_name, tool_args, target_dir, ts_module)

                msg_history.append({
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": str(exec_result) if not isinstance(exec_result, str) else exec_result,
                })

            if verdict_result is not None:
                return verdict_result

        else:
            plain_text = (api_msg.content or "").strip()
            logger.debug("[%s] Plain text response on step %d", agent_name, curr_step)

            extracted_json = extract_json_verdict(plain_text)
            if extracted_json:
                return normalise_verdict(extracted_json)

            if curr_step == max_steps:
                return fallback_verdict(raw_text=plain_text)

    return fallback_verdict(reason_msg="max_steps exceeded")


def normalise_verdict(raw_dict: dict) -> dict:
    final_verdict = dict(raw_dict)
    final_verdict.setdefault("verdict", "UNKNOWN")
    final_verdict.setdefault("confidence", 0)
    final_verdict.setdefault("severity", "INFO")
    final_verdict.setdefault("reasoning", "")
    return final_verdict


def fallback_verdict(error_msg: str = "", reason_msg: str = "", raw_text: str = "") -> dict:
    return {
        "verdict": "UNKNOWN",
        "confidence": 0,
        "severity": "INFO",
        "vuln_class": "N/A",
        "reasoning": f"Agent loop did not complete. {reason_msg} {error_msg}".strip(),
        "raw_response": raw_text[:500] if raw_text else "",
    }


def extract_json_verdict(raw_text: str) -> dict | None:
    import re
    match_fenced = re.search(r"```json\s*(\{.*?\})\s*```", raw_text, re.DOTALL)
    if match_fenced:
        try:
            return json.loads(match_fenced.group(1))
        except json.JSONDecodeError:
            pass
    
    match_bare = re.search(r"\{[^{}]{20,}\}", raw_text, re.DOTALL)
    if match_bare:
        try:
            return json.loads(match_bare.group(0))
        except json.JSONDecodeError:
            pass
    return None
