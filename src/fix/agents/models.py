from src.fix.agents.prompts import SYSTEM_PROMPT, USER_TEMPLATE
from src.tools.handlers import run_agent
from src.tools.schemas import FIX_TOOL_SET

def start_fix(
    finding_item: dict,
    source_code: str,
    cve_context: str = "None",
    model_name: str = None,
    target_dir: str = "",
    ts_module=None,
) -> dict:
    from main import MODELS
    resolved_model = model_name or MODELS[0]

    user_message = USER_TEMPLATE.format(
        rule  = finding_item.get("id", "Unknown Vulnerability"),
        msg   = finding_item.get("message", "No description provided."),
        path  = finding_item.get("path", "Unknown file"),
        dflow = finding_item.get("dataflow_trace", "No trace available."),
        code  = source_code,
        cve   = cve_context,
    )

    return run_agent(
        system_prompt   = SYSTEM_PROMPT,
        initial_message = user_message,
        tool_schemas    = FIX_TOOL_SET,
        target_dir      = target_dir,
        ts_module       = ts_module,
        model_name      = resolved_model,
        max_steps       = 5,
        agent_name      = "FIX",
    )
