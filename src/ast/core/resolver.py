import os
import re
from pathlib import Path
from src.ast.core.utils import *
from src.ast.rule.sanitizers import SANITIZERS
from src.ast.core.analyzer import has_sink

# Resolve aliases
def resolve_aliases(path: str, var: str) -> str:
    import re

    dir = Path(path)

    if not dir.exists():

        return f"File not found: {path}"

    ext = dir.suffix.lower()

    if ext not in LANG:
        with open(dir, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        regex = re.compile(rf"\b{re.escape(var)}\b")
        hits = [(idx + 1, text.rstrip()) for idx, text in enumerate(lines) if regex.search(text)]

        if not hits:

            return ""

        return "\n".join(f"  line {num:4d}: {code}" for num, code in hits[:30])

    try:
        with open(dir, "rb") as f:
            code = f.read()

        ts = Parser(Language(LANG[ext]))
        tree = ts.parse(code)

        chain = []
        bts = var.encode("utf-8")

        def visit(node):
            kind = node.type.lower()
            if any(k in kind for k in ("assign", "declar", "statement", "call", "invocation", "return")):
                text = code[node.start_byte:node.end_byte]

                if bts in text:
                    snippet = text.decode("utf-8", errors="ignore").strip()
                    line_num = node.start_point[0] + 1
                    if not any(num == line_num for num, _ in chain):
                        chain.append((line_num, snippet[:120]))

            for child in node.children:
                visit(child)

        visit(tree.root_node)

        if not chain:

            return ""

        outputs = [f"  line {num:4d}: {snippet}" for num, snippet in chain]

        return "\n".join(outputs)

    except Exception as err:

        return f"[resolve_aliases error] {err}"

# Resolve alias chain
def resolve_aliases_chain(path: str, var: str, hops: int = 5) -> str:
    import re
    seen = set()
    res = []
    
    def trace(curr, hop):
        if hop > hops or curr in seen:
            return
        seen.add(curr)
        raw = resolve_aliases(path, curr)
        if not raw or raw.startswith("File not found") or raw.startswith("[resolve_aliases error]"):
            return
        res.append(f"[STEP {hop}] {curr}:\n{raw}")
        
        for line in raw.splitlines():
            match = re.search(r'=\s*([a-zA-Z_]\w*)\b', line)
            if match:
                up = match.group(1)
                if up not in seen:
                    trace(up, hop + 1)
    
    trace(var, 1)
    if not res:
        return ""
    return "\n\n".join(res)

# Find sanitizer
def find_sanitizer(
    path: str,
    start: int,
    end: int,
) -> str:
    import re

    dir = Path(path)
    ext = dir.suffix.lower()

    if not dir.exists():

        return f"File not found: {path}"

    try:
        with open(dir, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()

    except Exception as err:

        return f"[find_sanitizer error] {err}"

    idx_start = max(0, start - 1)
    idx_end   = min(len(lines), end)
    region = lines[idx_start:idx_end]

    hits = []

    for i, text in enumerate(region, start=start):
        indent = len(text) - len(text.lstrip())
        
        # STRIP COMMENTS BEFORE CHECKING
        markers = {
            ".py": "#", ".js": "//", ".ts": "//", ".java": "//",
            ".go": "//", ".php": "//", ".cs": "//", ".c": "//", ".cpp": "//"
        }
        marker = markers.get(ext, "#")
        idx = text.find(marker)
        if idx != -1:
            text = text[:idx]

        for san in SANITIZERS:

            if re.search(san, text, re.IGNORECASE):
                stripped = text.strip()
                cond = stripped.startswith(("if ", "elif ", "else:", "except", "try:"))
                hits.append({
                    "line": i,
                    "text": stripped[:100],
                    "san": san,
                    "cond": cond,
                    "indent": indent,
                })
                break

    if not hits:

        return (

            f"[NO SANITIZER] No sanitizer detected between lines "
            f"{start}-{end} in {dir.name}. "
            "Taint path is likely unprotected."
        )

    all_cond = all(hit["cond"] or hit["indent"] > 0 for hit in hits)

    summary = [
        f"[SANITIZER ANALYSIS] {dir.name} lines {start}-{end}:"
    ]

    for hit in hits:
        flag = "CONDITIONAL" if hit["cond"] else "ON PATH"
        summary.append(f"  line {hit['line']:4d} [{flag}] {hit['text']}")

    if all_cond:
        summary.append(
            "  WARNING: All sanitizers are inside conditional branches "
            "- taint may reach sink on unprotected path."
        )

    else:
        summary.append(
            "  At least one sanitizer is on the direct execution path."
        )

    return "\n".join(summary)