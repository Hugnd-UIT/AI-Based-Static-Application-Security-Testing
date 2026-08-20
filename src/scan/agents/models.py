from src.scan.agents.prompts import SYSTEM_PROMPT, USER_TEMPLATE
from src.tools.handlers import run_agent
from src.tools.schemas import SCAN_TOOLS

def start_scan(
    finding_item: dict,
    source_code: str,
    model_name: str = None,
    target_dir: str = "",
    ts_module=None,
) -> dict:
    from main import MODELS
    resolved_model = model_name or MODELS[0]

    extra_context = ""

    if finding_item.get("sink_context"):
        extra_context = f"\n\n[RETRY WITH SURROGATE SINK]\n{finding_item['sink_context']}"

    user_message = USER_TEMPLATE.format(
        rule  = finding_item.get("id", "N/A"),
        msg   = finding_item.get("message", ""),
        path  = finding_item.get("path", ""),
        dflow = finding_item.get("dataflow_trace", "No dataflow trace provided."),
        code  = source_code + extra_context,
    )

    return run_agent(

        system_prompt   = SYSTEM_PROMPT,
        initial_message = user_message,
        tool_schemas    = SCAN_TOOLS,
        target_dir      = target_dir,
        ts_module       = ts_module,
        model_name      = resolved_model,
        max_steps       = 8,
        agent_name      = "SCAN",
    )
