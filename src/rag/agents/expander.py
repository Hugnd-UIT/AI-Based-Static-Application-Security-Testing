import json
from src.rag.agents.prompts import SINK_EXPANDER_PROMPT, SINK_EXPANDER_USER_TEMPLATE
from src.tools.handlers import run_agent
from src.tools.schemas import SINK_EXPAND_TOOL_SET

def start_expand(
    cve_context: str,
    model_name: str = None,
    target_dir: str = "",
    ts_module=None,
) -> dict:
    from main import MODELS
    resolved_model = model_name or MODELS[0]

    user_message = SINK_EXPANDER_USER_TEMPLATE.format(
        cve_context=cve_context
    )

    return run_agent(
        system_prompt   = SINK_EXPANDER_PROMPT,
        initial_message = user_message,
        tool_schemas    = SINK_EXPAND_TOOL_SET,
        target_dir      = target_dir,
        ts_module       = ts_module,
        model_name      = resolved_model,
        max_steps       = 6,
        agent_name      = "SINK_EXPANDER",
    )
