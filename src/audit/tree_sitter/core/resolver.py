import os
import re
from pathlib import Path
from src.audit.tree_sitter.core.utils import *
from src.audit.tree_sitter.rule.sanitizers import SANITIZERS
from src.audit.tree_sitter.core.analyzer import has_sink

# Hàm tìm kiếm alias
def resolve_aliases(path: str, var: str) -> str:
    import re

    dir = Path(path)

    if not dir.exists():

        return f"Không tìm thấy tập tin: {path}"

    ext = dir.suffix.lower()

    if ext not in LANG:
        with open(dir, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        regex = re.compile(rf"\b{re.escape(var)}\b")
        hits = [(idx + 1, text.rstrip()) for idx, text in enumerate(lines) if regex.search(text)]

        if not hits:

            return ""

        return "\n".join(f"  dòng {num:4d}: {code}" for num, code in hits[:30])

    try:
        with open(dir, "rb") as f:
            code = f.read()

        ts = Parser(Language(LANG[ext]))
        tree = ts.parse(code)

        chain = []
        bts = var.encode("utf-8")

        def visit(node):
            if node.type in (
                "assignment", "augmented_assignment",
                "variable_declarator", "local_variable_declaration",
                "expression_statement",
                "declaration", "init_declarator", "assignment_expression",
                "update_expression",
                "short_var_declaration", "assignment_statement",
                "call_expression", "call", "return_statement"
            ):
                text = code[node.start_byte:node.end_byte]

                if bts in text:
                    snippet = text.decode("utf-8", errors="ignore").strip()
                    chain.append((node.start_point[0] + 1, snippet[:120]))

            for child in node.children:
                visit(child)

        visit(tree.root_node)

        if not chain:

            return ""

        outputs = [f"  dòng {num:4d}: {snippet}" for num, snippet in chain]

        return "\n".join(outputs)

    except Exception as err:

        return f"[lỗi resolve_aliases] {err}"

# Hàm tìm kiếm chuỗi alias
def resolve_aliases_chain(path: str, var: str, hops: int = 5) -> str:
    import re
    seen = set()
    res = []
    
    def trace(curr, hop):
        if hop > hops or curr in seen:
            return
        seen.add(curr)
        raw = resolve_aliases(path, curr)
        if not raw or raw.startswith("File not found") or raw.startswith("[lỗi resolve_aliases]"):
            return
        res.append(f"[BƯỚC {hop}] {curr}:\n{raw}")
        
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

# Hàm tìm kiếm sanitizer
def find_sanitizer(
    path: str,
    start: int,
    end: int,
) -> str:
    import re

    dir = Path(path)
    ext = dir.suffix.lower()

    if not dir.exists():

        return f"Không tìm thấy tập tin: {path}"

    try:
        with open(dir, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()

    except Exception as err:

        return f"[lỗi find_sanitizer] {err}"

    idx_start = max(0, start - 1)
    idx_end   = min(len(lines), end)
    region = lines[idx_start:idx_end]

    hits = []

    for i, text in enumerate(region, start=start):
        indent = len(text) - len(text.lstrip())
        
        # BỎ COMMENT TRƯỚC KHI KIỂM TRA
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

            f"[KHÔNG CÓ SANITIZER] Không phát hiện sanitizer nào giữa các dòng "
            f"{start}-{end} trong {dir.name}. "
            "Đường dẫn taint có khả năng không được bảo vệ."
        )

    all_cond = all(hit["cond"] or hit["indent"] > 0 for hit in hits)

    summary = [
        f"[PHÂN TÍCH SANITIZER] {dir.name} dòng {start}-{end}:"
    ]

    for hit in hits:
        flag = "CÓ ĐIỀU KIỆN" if hit["cond"] else "TRÊN ĐƯỜNG DẪN"
        summary.append(f"  dòng {hit['line']:4d} [{flag}] {hit['text']}")

    if all_cond:
        summary.append(
            "  CẢNH BÁO: Tất cả sanitizer đều nằm trong nhánh điều kiện "
            "- taint có thể chạm đến điểm sink trên đường dẫn không được sanitize."
        )

    else:
        summary.append(
            "  Ít nhất một sanitizer nằm trên đường dẫn thực thi trực tiếp."
        )

    return "\n".join(summary)

