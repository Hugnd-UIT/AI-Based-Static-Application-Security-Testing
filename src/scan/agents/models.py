from src.scan.agents.prompts import SYSTEM, USER
from src.tools.handlers import run_agent
from src.tools.schemas import SCAN_TOOLS

# Hàm gọi scanning agent
def start_scan(
    finding: dict,
    code: str,
    model: str = None,
    target: str = "",
    module=None,
) -> dict:
    from main import MODELS
    resolved = model or MODELS[0]

    extra = ""

    if finding.get("sink_context"):
        extra = f"\n\n[RETRY WITH SURROGATE SINK]\n{finding['sink_context']}"

    message = USER.format(
        rule  = finding.get("id", "N/A"),
        msg   = finding.get("message", ""),
        path  = finding.get("path", ""),
        dflow = finding.get("dataflow_trace", "No dataflow trace provided."),
        code  = code + extra,
    )

    return run_agent(
        prompt    = SYSTEM,
        message   = message,
        schemas   = SCAN_TOOLS,
        directory = target,
        module    = module,
        model     = resolved,
        steps     = 15,
        agent     = "SCAN",
    )
