from src.fix.agents.prompts import SYSTEM, USER
from src.tools.handlers import run_agent
from src.tools.schemas import FIX_TOOLS

# Hàm xử lý fix lỗi
def start_fix(
    item: dict,
    code: str,
    context: str = "None",
    model: str = None,
    target: str = "",
    module=None,
) -> dict:
    from src.config import MODELS, STEPS
    use = model or MODELS[0]

    msg = USER.format(
        rule  = item.get("id", "Unknown Vulnerability"),
        msg   = item.get("message", "No description provided."),
        path  = item.get("path", "Unknown file"),
        dflow = item.get("dataflow_trace", "No trace available."),
        code  = code,
        cve   = context,
    )

    return run_agent(

        prompt   = SYSTEM,
        message = msg,
        schemas    = FIX_TOOLS,
        directory      = target,
        module       = module,
        model      = use,
        steps       = min(5, STEPS),
        agent      = "FIX",
    )
