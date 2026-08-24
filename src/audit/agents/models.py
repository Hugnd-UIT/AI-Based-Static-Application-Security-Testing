from src.audit.agents.prompts import SYSTEM, USER
from src.tools.handlers import run_agent
from src.tools.schemas import AUDIT_TOOLS

# Hàm xử lý phán quyết
def start_audit(
    item: dict,
    code: str,
    context: str = "None",
    model: str = None,
    target: str = "",
    module=None,
) -> dict:
    from main import MODELS
    use = model or MODELS[0]

    msg = USER.format(
        rule  = item.get("id", "N/A"),
        msg   = item.get("message", ""),
        path  = item.get("path", ""),
        dflow = item.get("dataflow_trace", "No dataflow trace provided."),
        code  = code,
        cve   = context,
    )

    return run_agent(

        prompt   = SYSTEM,
        message = msg,
        schemas    = AUDIT_TOOLS,
        directory      = target,
        module       = module,
        model      = use,
        steps       = 20,
        agent      = "AUDIT",
    )
