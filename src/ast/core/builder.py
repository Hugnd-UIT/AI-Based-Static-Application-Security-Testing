import os
from pathlib import Path
from tree_sitter import Parser, Language
from src.ast.rule.langs import LANG
from src.ast.core.utils import *
from src.ast.core.analyzer import *

from src.audit.frameworks import extract_events

# Build pub/sub map
def build_pubsub(dir: str) -> str:
    if not dir or not Path(dir).exists():

        return ""

    info = []
    
    for root, subs, files in os.walk(dir):
        subs[:] = [d for d in subs if d not in {".git", "node_modules", "vendor", ".venv", "__pycache__"}]

        for file in files:
            ext = Path(file).suffix.lower()

            if ext not in LANG: continue
            
            path = Path(root) / file

            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    text = f.read()
                
                pubs, _subs = extract_events(text, ext)

                if pubs:
                    info.append(f"[EVENT PUBLISHER IN {file}]\nEmits: {', '.join(pubs)}")

                if _subs:
                    info.append(f"[EVENT SUBSCRIBER IN {file}]\nListens: {', '.join(_subs)}")

            except Exception:
                pass
                
    return "\n\n".join(info)

# Build context
def build_context(dir: str) -> str:
    if not dir or not Path(dir).exists():

        return ""

    funcs = get_tainted(dir)
    cross = find_sinks(dir, funcs) if funcs else ""
    pubsub = build_pubsub(dir)
    
    ctx = ""

    if cross:
        ctx += cross + "\n\n"

    if pubsub:
        ctx += "EVENT BUS / PUB-SUB ARCHITECTURE\n" + pubsub + "\n"
        
    return ctx

# Extract context
def extract_context(
    path: str,
    start: int,
    end: int,
    dir: str = None,
    depth: int = 2,
) -> str:
    fpath = Path(path)

    if not fpath.exists():

        return ""

    ext = fpath.suffix.lower()

    if ext not in LANG:

        return extract_chunk(fpath, start, end)

    try:
        parser = Parser(Language(LANG[ext]))

        with open(fpath, "rb") as f:
            code = f.read()

        tree = parser.parse(code)
        node, groups = find_func(tree.root_node, start, end)

        if not node:

            return extract_chunk(fpath, start, end)

        scode = extract_code(code, node)

        if groups:
            meta = f"// Vulnerability inside: {', '.join(groups)}\n"
            scode = meta + scode

        sname = get_node(node, code)

        if not sname or depth < 1:

            return f"[SINK POINT]\n{scode}"

        ctx = ""

        if dir:
            ctx += find_calls(dir, sname, ext, parser)

        else:
            callers = find_callers(tree.root_node, sname, code)

            for cnode in callers:
                ccode = extract_code(code, cnode)
                ctx += f"[CALLER]\n{ccode}\n\n"

        ctx += f"[SINK POINT]\n{scode}"

        return ctx

    except Exception:

        return extract_chunk(fpath, start, end)
