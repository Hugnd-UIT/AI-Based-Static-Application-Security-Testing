import os
from pathlib import Path
from tree_sitter import Parser, Language
from src.ast.rule.langs import LANG

# Hàm trích xuất code
def extract_code(code: bytes, node) -> str:
    return code[node.start_byte : node.end_byte].decode("utf-8")

# Hàm lấy node
def get_node(node, code: bytes) -> str:
    for child in node.children:

        if child.type == "identifier" or child.type == "name":

            return extract_code(code, child)

    return None

# Hàm tìm hàm
def find_func(node, start: int, end: int):
    idx_start = start - 1
    idx_end = end - 1

    match = None
    groups = []

    def traverse(curr):
        nonlocal match

        if curr.start_point[0] <= idx_start and curr.end_point[0] >= idx_end:
            kind = curr.type.lower()

            if "function" in kind or "method" in kind or "declaration" in kind:
                match = curr

            elif (
                "if_statement" in kind
                or "try_statement" in kind
                or "for_statement" in kind
                or "while_statement" in kind
            ):

                if kind not in groups:
                    groups.append(kind)

            for child in curr.children:
                traverse(child)

    traverse(node)

    return match, groups

# Hàm kiểm tra có phải là hàm
def is_func(kind: str) -> bool:
    return (

        kind in (
            "function_definition", "function_declaration",
            "method_declaration", "method_definition",
            "function_item", "func_declaration",
        )
        or "function" in kind
        or "method" in kind
    )

# Hàm trích xuất khối code
def extract_chunk(path: Path, start: int, end: int, pad: int = 15) -> str:
    with open(path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    idx_start = max(0, start - 1 - pad)
    idx_end = min(len(lines), end + pad)

    return "".join(lines[idx_start:idx_end])

_code_cache = {}

# Hàm lấy code implementation
def get_code(dir: str, func: str) -> str:
    key = (dir, func)
    if key in _code_cache: return _code_cache[key]
    
    for root, subs, files in os.walk(dir):
        subs[:] = [d for d in subs if d not in {".git", "node_modules", "vendor", ".venv", "__pycache__"}]

        for file in files:
            ext = Path(file).suffix.lower()

            if ext not in LANG: continue
            path = Path(root) / file

            try:
                with open(path, "rb") as f:
                    content = f.read()
                
                if func.encode("utf-8") not in content:
                    continue

                parser = Parser(Language(LANG[ext]))
                tree = parser.parse(content)

                match = ""

                def find(node):
                    nonlocal match

                    if match: return
                    kind = node.type.lower()

                    if is_func(kind) and get_node(node, content) == func:
                        match = content[node.start_byte:node.end_byte].decode("utf-8", errors="ignore")
                        return

                    for child in node.children:
                        find(child)

                find(tree.root_node)

                if match:

                    _code_cache[key] = f"[TRIỂN KHAI CỦA {func} TRONG {file}]\n{match}"
                    return _code_cache[key]

            except Exception:
                pass

    _code_cache[key] = f"// Hàm {func} không tìm thấy trong kho mã nguồn."
    return _code_cache[key]

# Hàm lấy tất cả các hàm gọi
def get_all_calls(node):
    calls = []
    def traverse(n):
        if "call" in n.type.lower() or "invocation" in n.type.lower():
            calls.append(n)
        for c in n.children:
            traverse(c)
    traverse(node)
    return calls

# Hàm lấy tên hàm gọi
def get_call_name(node, content):
    for child in node.children:
        if child.type == "identifier":
            return content[child.start_byte:child.end_byte].decode("utf-8", errors="ignore")
        elif child.type in ("attribute", "member_expression"):
            for gchild in child.children:
                if gchild.type in ("property_identifier", "identifier"):
                    return content[gchild.start_byte:gchild.end_byte].decode("utf-8", errors="ignore")
    return None
