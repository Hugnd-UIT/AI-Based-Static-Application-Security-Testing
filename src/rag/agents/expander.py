import json
from src.rag.agents.prompts import EXPAND, ETMP
from src.tools.handlers import run_agent
from src.tools.schemas import EXPAND_TOOLS

# Hàm mở rộng sink
def start_expand(
    context: str,
    model: str = None,
    target: str = "",
    module=None,
) -> dict:
    from main import MODELS
    use = model or MODELS[0]

    msg = ETMP.format(
        context=context
    )

    return run_agent(

        prompt   = EXPAND,
        message = msg,
        schemas    = EXPAND_TOOLS,
        directory      = target,
        module       = module,
        model      = use,
        steps       = 6,
        agent      = "SINK_EXPANDER",
    )