import json
from src.rag.agents.prompts import POC_VERIFIER_PROMPT, POC_VERIFIER_USER_TEMPLATE
from src.tools.handlers import run_agent
from src.tools.schemas import POC_VERIFY_TOOL_SET

def start_verify(
    cve_summary: str,
    model_name: str = None,
    target_dir: str = "",
    ts_module=None,
) -> dict:
    from main import MODELS
    resolved_model = model_name or MODELS[0]

    user_message = POC_VERIFIER_USER_TEMPLATE.format(
        cve_summary=cve_summary
    )

    return run_agent(
        system_prompt   = POC_VERIFIER_PROMPT,
        initial_message = user_message,
        tool_schemas    = POC_VERIFY_TOOL_SET,
        target_dir      = target_dir,
        ts_module       = ts_module,
        model_name      = resolved_model,
        max_steps       = 12,
        agent_name      = "POC_VERIFIER",
    )
