import json
from src.rag.agents.prompts import EXPAND_PROMPT, EXPAND_TEMPLATE
from src.tools.handlers import run_agent
from src.tools.schemas import EXPAND_TOOLS

def start_expand(
    cve_context: str,
    model_name: str = None,
    target_dir: str = "",
    ts_module=None,
) -> dict:
    from main import MODELS
    use_model = model_name or MODELS[0]

    use_msg = EXPAND_TEMPLATE.format(
        cve_context=cve_context
    )

    return run_agent(

        system_prompt   = EXPAND_PROMPT,
        initial_message = use_msg,
        tool_schemas    = EXPAND_TOOLS,
        target_dir      = target_dir,
        ts_module       = ts_module,
        model_name      = use_model,
        max_steps       = 6,
        agent_name      = "SINK_EXPANDER",
    )
