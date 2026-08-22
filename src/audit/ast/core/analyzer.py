import os
import re
from pathlib import Path
from tree_sitter import Parser, Language
from src.audit.ast.rule.langs import LANG
from src.audit.ast.rule.sources import SOURCES
from src.audit.ast.rule.sinks import SINKS
from src.audit.ast.core.utils import *

# Hàm tìm nguồn gọi
def find_callers(root, name: str, code: bytes):
    callers = []

    def traverse(curr, func):
        kind = curr.type.lower()

        if is_func(kind):
            func = curr

        if "call" in kind or "invocation" in kind:
            ident = None

            for child in curr.children:

                if child.type == "identifier":
                    ident = child
                    break

                elif child.type in ("attribute", "member_expression", "field_expression"):

                    for gchild in child.children:

                        if "identifier" in gchild.type:
                            ident = gchild
                            
            if ident:
                val = extract_code(code, ident)

                if val == name and func:

                    if func not in callers:
                        callers.append(func)

        for child in curr.children:
            traverse(child, func)

    traverse(root, None)

    return callers

# Hàm tìm điểm gọi
def find_calls(dir: str, name: str, ext: str, parser: Parser):
    ctx = ""

    if not dir or not Path(dir).exists():

        return ""

    for root, _, files in os.walk(dir):

        if ".git" in root or "node_modules" in root or "vendor" in root:
            continue

        for file in files:

            if not file.endswith(ext):
                continue

            path = Path(root) / file

            try:
                with open(path, "rb") as f:
                    content = f.read()

                tree = parser.parse(content)
                callers = find_callers(tree.root_node, name, content)

                for caller in callers:
                    code = extract_code(content, caller)
                    ctx += f"[HÀM GỌI TRONG {file}]\n{code}\n\n"

            except Exception:
                pass

    return ctx

from src.audit.frameworks import check_entrypoint

# Hàm kiểm tra có nguồn taint
def has_source(content: bytes, node, ext: str = "") -> bool:
    try:
        text = content[node.start_byte:node.end_byte].decode("utf-8", errors="ignore")

        if any(src in text for src in SOURCES):

            return True

        if ext and check_entrypoint(text, ext):

            return True

        return False

    except Exception:

        return False

import re
SINKS_PATTERNS = [re.compile(r'\b' + re.escape(s) + r'\b') for s in SINKS]

# Hàm kiểm tra có điểm sink
def has_sink(content: bytes, node) -> bool:
    try:
        text = content[node.start_byte:node.end_byte].decode("utf-8", errors="ignore")
        return any(p.search(text) for p in SINKS_PATTERNS)
    except Exception:
        return False

# Hàm quét các hàm được gọi
def scan_callees(node, content, dir, depth=0, max=2):
    if depth > max: return False
    if has_sink(content, node): return True
    
    for call in get_all_calls(node):
        callee = get_call_name(call, content)
        if callee:
            code = get_code(dir, callee)
            if code and not code.startswith("//"):
                if any(p.search(code) for p in SINKS_PATTERNS):
                    return True
    return False

# Hàm lấy các hàm bị taint
def get_tainted(dir: str) -> dict:
    funcs = {}

    for root, subs, files in os.walk(dir):
        subs[:] = [d for d in subs if d not in {".git", "node_modules", "vendor", ".venv", "__pycache__"}]

        for file in files:
            ext = Path(file).suffix.lower()

            if ext not in LANG:
                continue

            path = Path(root) / file

            try:
                with open(path, "rb") as f:
                    content = f.read()

                parser = Parser(Language(LANG[ext]))
                tree = parser.parse(content)

                def traverse(node):
                    kind = node.type.lower()

                    if is_func(kind) and has_source(content, node, ext):
                        name = get_node(node, content)
                        code = content[node.start_byte:node.end_byte].decode("utf-8", errors="ignore")

                        if name and name not in funcs:
                            funcs[name] = {"file": str(path), "code": code[:800]}

                    for child in node.children:
                        traverse(child)

                traverse(tree.root_node)

            except Exception:
                pass

    return funcs

# Hàm tìm điểm sink
def find_sinks(dir: str, funcs: dict) -> str:
    if not funcs:

        return ""

    paths = []
    names = set(funcs.keys())

    for root, subs, files in os.walk(dir):
        subs[:] = [d for d in subs if d not in {".git", "node_modules", "vendor", ".venv", "__pycache__"}]

        for file in files:
            ext = Path(file).suffix.lower()

            if ext not in LANG:
                continue

            path = Path(root) / file

            try:
                with open(path, "rb") as f:
                    content = f.read()

                text = content.decode("utf-8", errors="ignore")
                called = [fn for fn in names if fn in text]

                if not called:
                    continue

                parser = Parser(Language(LANG[ext]))
                tree = parser.parse(content)

                def scan(curr, parent=None):
                    kind = curr.type.lower()

                    if is_func(kind):
                        parent = curr

                    if ("call" in kind or "invocation" in kind) and parent:
                        ident = None

                        for child in curr.children:

                            if child.type == "identifier":
                                ident = child
                                break

                            elif child.type in ("attribute", "member_expression"):

                                for gchild in child.children:

                                    if gchild.type == "property_identifier" or gchild.type == "identifier":
                                        ident = gchild
                                        
                        if ident:
                            func = content[ident.start_byte:ident.end_byte].decode("utf-8", errors="ignore")

                            if func in called and scan_callees(parent, content, dir):
                                origin = funcs.get(func, {})
                                ptext = content[parent.start_byte:parent.end_byte].decode("utf-8", errors="ignore")
                                entry = (
                                    f"[PHÁT HIỆN ĐƯỜNG DẪN TAINT LIÊN TẬP TIN]\n"
                                    f"  Nguồn Taint : {func} in {origin.get('file', 'unknown')}\n"
                                    f"  Lan truyền tới: {file} (line {curr.start_point[0] + 1})\n"
                                    f"  Hàm gọi:\n{ptext[:600]}\n"
                                    f"  Hàm gốc:\n{origin.get('code', '')[:400]}\n"
                                )

                                if entry not in paths:
                                    paths.append(entry)

                    for child in curr.children:
                        scan(child, parent)

                scan(tree.root_node)

            except Exception:
                pass

    return "\n".join(paths)