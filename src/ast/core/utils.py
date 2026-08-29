import os
from pathlib import Path
from tree_sitter import Parser, Language
from src.ast.rule.langs import LANG

# Extract code
def extract_code(code: bytes, node) -> str:
    return code[node.start_byte : node.end_byte].decode("utf-8")

# Get node
def get_node(node, code: bytes) -> str:
    for child in node.children:
        if child.type == "identifier" or child.type == "name":
            return extract_code(code, child)
    return None

# Extract code chunk
def extract_chunk(path: Path, start: int, end: int, pad: int = 15) -> str:
    with open(path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    idx_start = max(0, start - 1 - pad)
    idx_end = min(len(lines), end + pad)

    return "".join(lines[idx_start:idx_end])

_parsers = {}

# Get cached parser
def get_parser(ext: str):
    if ext not in LANG: return None
    if ext not in _parsers:
        _parsers[ext] = Parser(Language(LANG[ext]))
    return _parsers[ext]

def get_func_nodes(root_node, ext: str, code: bytes) -> dict:
    from src.ast.rule.queries import QUERIES
    from src.ast.rule.langs import EXT, LANG
    from tree_sitter import Language, Query, QueryCursor

    lang_name = EXT.get(ext)
    if not lang_name: return {}

    query_src = QUERIES.get(lang_name, "")
    if not query_src.strip(): return {}

    try:
        lang_obj = LANG.get(ext)
        if not lang_obj: return {}
        language = Language(lang_obj)
        query = Query(language, query_src)
        cursor = QueryCursor(query)
        captures = cursor.captures(root_node)
    except Exception:
        return {}

    func_nodes = captures.get("func", [])
    name_nodes = {n.start_byte: n for n in captures.get("name", [])}

    funcs = {}
    for node in func_nodes:
        name = ""
        for nbyte, nnode in name_nodes.items():
            if node.start_byte <= nbyte <= node.end_byte:
                name = code[nnode.start_byte:nnode.end_byte].decode("utf-8", errors="ignore")
                break
        if not name:
            name = "[anonymous:%d]" % (node.start_point[0] + 1)
        funcs[node] = name

    return funcs

def get_calls(node, content: bytes) -> dict:
    calls = {}
    
    def traverse(curr):
        kind = curr.type.lower()
        if "call" in kind or "invocation" in kind:
            ident = None
            for child in curr.children:
                if child.type == "identifier":
                    ident = child
                    break
                elif child.type in ("attribute", "member_expression"):
                    for gchild in child.children:
                        if gchild.type in ("property_identifier", "identifier"):
                            ident = gchild
                            
            if ident:
                name = content[ident.start_byte:ident.end_byte].decode("utf-8", errors="ignore")
                calls[curr] = name
                
        for child in curr.children:
            traverse(child)

    traverse(node)
    return calls

def find_func(root_node, start: int, end: int, ext: str, content: bytes):
    idx_start = start - 1
    idx_end = end - 1

    match = None
    groups = []
    
    func_nodes = get_func_nodes(root_node, ext, content)

    def traverse(curr):
        nonlocal match

        if curr.start_point[0] <= idx_start and curr.end_point[0] >= idx_end:
            if curr in func_nodes:
                match = curr
                
            kind = curr.type.lower()
            if (
                "if_statement" in kind
                or "try_statement" in kind
                or "for_statement" in kind
                or "while_statement" in kind
            ):
                if kind not in groups:
                    groups.append(kind)

            for child in curr.children:
                traverse(child)

    traverse(root_node)
    return match, groups

def get_function_at(path: str, line: int) -> str:
    ext = Path(path).suffix.lower()
    parser = get_parser(ext)
    if not parser: return "Unknown"

    try:
        with open(path, "rb") as f:
            content = f.read()

        tree = parser.parse(content)
        func_nodes = get_func_nodes(tree.root_node, ext, content)
        
        idx = line - 1
        for node, name in func_nodes.items():
            if node.start_point[0] <= idx and node.end_point[0] >= idx:
                return name

        return "Unknown"

    except Exception:
        return "Unknown"

_code_cache = {}

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
                
                if func != "[global]" and func.encode("utf-8") not in content:
                    continue

                parser = get_parser(ext)
                tree = parser.parse(content)

                func_nodes = get_func_nodes(tree.root_node, ext, content)

                if func == "[global]":
                    func_lines = set()
                    for node in func_nodes:
                        func_lines.update(range(node.start_point[0] + 1, node.end_point[0] + 2))
                    
                    text = content.decode("utf-8", errors="ignore")
                    global_lines = [
                        line for i, line in enumerate(text.splitlines(), 1)
                        if i not in func_lines and line.strip() and not line.strip().startswith("#") and not line.strip().startswith("//")
                    ]
                    
                    if global_lines:
                        body = "\n".join(global_lines)
                        _code_cache[key] = f"[IMPLEMENTATION OF [global] IN {file}]\n{body}"
                        return _code_cache[key]
                    continue

                for node, name in func_nodes.items():
                    if name == func:
                        match = content[node.start_byte:node.end_byte].decode("utf-8", errors="ignore")
                        _code_cache[key] = f"[IMPLEMENTATION OF {func} IN {file}]\n{match}"
                        return _code_cache[key]

            except Exception:
                pass

    _code_cache[key] = f"// Function {func} not found in repository."
    return _code_cache[key]