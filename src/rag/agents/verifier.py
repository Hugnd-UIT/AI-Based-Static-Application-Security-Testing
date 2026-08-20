import json
from src.rag.agents.prompts import VERIFY_PROMPT, VERIFY_TEMPLATE
from src.tools.handlers import run_agent
from src.tools.schemas import VERIFY_TOOLS

def start_verify(
    cve_summary: str,
    model_name: str = None,
    target_dir: str = "",
    ts_module=None,
) -> dict:
    from main import MODELS
    use_model = model_name or MODELS[0]

    use_msg = VERIFY_TEMPLATE.format(
        cve_summary=cve_summary
    )

    return run_agent(

        system_prompt   = VERIFY_PROMPT,
        initial_message = use_msg,
        tool_schemas    = VERIFY_TOOLS,
        target_dir      = target_dir,
        ts_module       = ts_module,
        model_name      = use_model,
        max_steps       = 12,
        agent_name      = "POC_VERIFIER",
    )
