import json
from src.rag.agents.prompts import VERIFY, VTMP
from src.tools.handlers import run_agent
from src.tools.schemas import VERIFY_TOOLS

# Hàm kiểm tra PoC
def start_verify(
    summary: str,
    model: str = None,
    target: str = "",
    module=None,
) -> dict:
    from main import MODELS
    use = model or MODELS[0]

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