import json
from src.rag.agents.prompts import VERIFY, VTMP
from src.tools.handlers import run_agent
from src.tools.schemas import VERIFY_TOOLS

def start_verify(
    summary: str,
    model: str = None,
    target: str = "",
    module=None,
) -> dict:
    import os
    use = model or os.environ["AI_MODEL"]

    msg = VTMP.format(
        summary=summary
    )

    return run_agent(

        prompt   = VERIFY,
        message = msg,
        schemas    = VERIFY_TOOLS,
        directory      = target,
        module       = module,
        model      = use,
        steps       = 20,
        agent      = "POC_VERIFIER",
    )