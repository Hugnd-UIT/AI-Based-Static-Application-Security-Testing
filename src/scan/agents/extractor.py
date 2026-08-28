import os
import re

EXTS = {
    ".js":    "javascript",
    ".jsx":   "javascript",
    ".mjs":   "javascript",
    ".cjs":   "javascript",
    ".py":    "python",
    ".java":  "java",
    ".rb":    "ruby",
    ".rs":    "rust",
    ".scala": "scala",
    ".php":   "php",
    ".ts":    "typescript",
    ".tsx":   "typescript",
    ".cs":    "csharp",
    ".go":    "go",
    ".cpp":   "cpp",
    ".cc":    "cpp",
    ".cxx":   "cpp",
    ".hpp":   "cpp",
    ".c":     "c",
    ".h":     "c",
}

REGEX = {
    "python":     re.compile(r'^\s*(?:async\s+)?def\s+([a-zA-Z_]\w*)\s*\([^)]*\):', re.MULTILINE),
    "javascript": re.compile(r'(?:function\s+([a-zA-Z_]\w*)\s*\(|([a-zA-Z_]\w*)\s*[:=]\s*(?:async\s+)?(?:function\s*)?\(|([a-zA-Z_]\w*)\s*[:=]\s*(?:async\s+)?(?:\w+|\([^)]*\))\s*=>)', re.MULTILINE),
    "typescript": re.compile(r'(?:function\s+([a-zA-Z_]\w*)\s*\(|([a-zA-Z_]\w*)\s*[:=]\s*(?:async\s+)?(?:function\s*)?\(|([a-zA-Z_]\w*)\s*[:=]\s*(?:async\s+)?(?:\w+|\([^)]*\))\s*=>)', re.MULTILINE),
    "java":       re.compile(r'(?:public|protected|private|static|\s)+[\w\<\>\[\]]+\s+([a-zA-Z_]\w*)\s*\([^\)]*\)\s*(?:throws\s+[\w\s,]+)?\s*\{', re.MULTILINE),
    "ruby":       re.compile(r'^\s*def\s+([a-zA-Z_]\w*[=!?]?)', re.MULTILINE),
    "rust":       re.compile(r'^\s*(?:pub\s+)?(?:async\s+)?fn\s+([a-zA-Z_]\w*)\s*\(', re.MULTILINE),
    "scala":      re.compile(r'^\s*(?:private|protected|override|\s)*def\s+([a-zA-Z_]\w*)\s*\(', re.MULTILINE),
    "php":        re.compile(r'(?:public|protected|private|static|\s)*function\s+([a-zA-Z_]\w*)\s*\(', re.MULTILINE),
    "csharp":     re.compile(r'(?:public|protected|private|internal|static|\s)+[\w\<\>\[\]]+\s+([a-zA-Z_]\w*)\s*\([^\)]*\)\s*\{', re.MULTILINE),
    "go":         re.compile(r'^\s*func\s+(?:\[[^\]]+\]\s+)?(?:\([^)]+\)\s+)?([a-zA-Z_]\w*)\s*\(', re.MULTILINE),
    "cpp":        re.compile(r'^\s*(?:virtual|static|inline|\s)*[\w\<\>\[\]\*\&]+\s+([a-zA-Z_]\w*)\s*\([^\)]*\)\s*(?:const)?\s*(?:override)?\s*\{', re.MULTILINE),
    "c":          re.compile(r'^\s*(?:static|inline|\s)*[\w\<\>\[\]\*\&]+\s+([a-zA-Z_]\w*)\s*\([^\)]*\)\s*\{', re.MULTILINE),
}

SKIP = {'node_modules', 'vendor', 'target', 'build', 'dist', '.git', '__pycache__', 'venv', '.venv', 'bin', 'obj'}

# Dynamically load tree-sitter module
def load_ts():
    try:
        import importlib.util
        from pathlib import Path
        p = Path(__file__).parent.parent.parent / "ast" / "tree-sitter.py"
        spec = importlib.util.spec_from_file_location("ts_mod", str(p.resolve()))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    except Exception:
        return None

QUERIES: dict[str, str] = {
    "python": """
        (function_definition name: (identifier) @name) @func
        (lambda) @func
    """,
    "javascript": """
        (function_declaration name: (identifier) @name) @func
        (function name: (identifier) @name) @func
        (arrow_function) @func
        (method_definition name: (property_identifier) @name) @func
    """,
    "typescript": """
        (function_declaration name: (identifier) @name) @func
        (function name: (identifier) @name) @func
        (arrow_function) @func
        (method_definition name: (property_identifier) @name) @func
    """,
    "java": """
        (method_declaration name: (identifier) @name) @func
        (constructor_declaration name: (identifier) @name) @func
        (lambda_expression) @func
    """,
    "ruby": """
        (method name: (identifier) @name) @func
        (singleton_method name: (identifier) @name) @func
        (lambda) @func
    """,
    "rust": """
        (function_item name: (identifier) @name) @func
        (closure_expression) @func
    """,
    "go": """
        (function_declaration name: (identifier) @name) @func
        (method_declaration name: (field_identifier) @name) @func
        (func_literal) @func
    """,
    "php": """
        (function_definition name: (name) @name) @func
        (method_declaration name: (name) @name) @func
        (arrow_function) @func
    """,
    "csharp": """
        (method_declaration name: (identifier) @name) @func
        (constructor_declaration name: (identifier) @name) @func
        (lambda_expression) @func
        (anonymous_method_expression) @func
    """,
    "scala": """
        (function_definition name: (identifier) @name) @func
    """,
    "cpp": """
        (function_definition declarator: (function_declarator declarator: (identifier) @name)) @func
    """,
    "c": """
        (function_definition declarator: (function_declarator declarator: (identifier) @name)) @func
    """,
}

def get_name_node(node, code: bytes) -> str:
    name_node = node.child_by_field_name('name')
    if name_node and name_node.type in ("identifier", "name"):
        return code[name_node.start_byte:name_node.end_byte].decode("utf-8", errors="ignore")

    queue = [node]
    while queue:
        curr = queue.pop(0)
        if curr != node and curr.type in ("identifier", "name"):
            return code[curr.start_byte:curr.end_byte].decode("utf-8", errors="ignore")
        
        for ch in curr.children:
            t = ch.type.lower()
            if "parameter" not in t and "block" not in t and "statement" not in t and "body" not in t:
                queue.append(ch)
                
    return ""

# Extract functions using tree-sitter API
def extract_ts(fpath: str, lang_obj, code: bytes, lang: str, rel: str) -> list:
    from tree_sitter import Parser, Language, Query
    language = Language(lang_obj)
    parser = Parser(language)
    tree = parser.parse(code)
    results = []
    seen = set()

    query_src = QUERIES.get(lang, "")
    if not query_src.strip():
        return []

    try:
        query = language.query(query_src)
        captures = query.captures(tree.root_node)
    except Exception:
        return []

    func_nodes = captures.get("func", [])
    name_nodes = {n.start_byte: n for n in captures.get("name", [])}

    for node in func_nodes:
        # Find the @name node that starts inside this @func node
        name = ""
        for nbyte, nnode in name_nodes.items():
            if node.start_byte <= nbyte <= node.end_byte:
                name = code[nnode.start_byte:nnode.end_byte].decode("utf-8", errors="ignore")
                break

        if not name:
            name = f"[anonymous:{node.start_point[0]+1}]"

        if name in seen:
            continue
        seen.add(name)

        sig_lines = code[node.start_byte:node.end_byte].decode("utf-8", errors="ignore").splitlines()
        sig  = sig_lines[0].strip() if sig_lines else name
        
        # Truncate body at 2000 chars
        full = "\n".join(sig_lines[1:])
        body = full[:2000] + (" ..." if len(full) > 2000 else "")

        results.append({
            "file":       rel,
            "function":   name,
            "signature":  sig,
            "context":    "",
            "body":       body,
            "language":   lang,
            "kind":       "definition",
            "start_line": node.start_point[0] + 1,
            "end_line":   node.end_point[0] + 1,
        })

    return results

# Extract functions using regex fallback
def extract_regex(fpath: str, content: str, lang: str, rel: str) -> list:
    pat = REGEX.get(lang)
    if not pat:
        return []
    results = []
    for m in pat.finditer(content):
        name = next((g for g in m.groups() if g), "anonymous")
        start = m.start()
        sig = " ".join(m.group(0).split())
        if sig.endswith("{") or sig.endswith(":"):
            sig = sig[:-1].strip()
        elif sig.endswith("=>"):
            sig = sig[:-2].strip()

        body = ""
        b = content.find('{', start)
        if b != -1:
            # Truncate body at 2000 chars   
            raw = content[b:b + 2000]
            body = raw + (" ..." if len(content) - b > 2000 else "")

        sl = content[:start].count('\n') + 1

        results.append({
            "file":      rel,
            "function":  name,
            "signature": sig,
            "context":   "",
            "body":      body,
            "language":  lang,
            "kind":      "definition",
            "start_line": sl,
            "end_line":   sl + 5,
        })
    return results

# Extract all functions in directory
def extract_functions(target_dir: str) -> list:
    ts = load_ts()
    results = []

    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d not in SKIP]

        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            lang = EXTS.get(ext)
            if not lang:
                continue

            fpath = os.path.join(root, fname)
            rel   = os.path.relpath(fpath, target_dir).replace("\\", "/")

            try:
                with open(fpath, "rb") as f:
                    raw = f.read()
                content = raw.decode("utf-8", errors="replace")

                if ts and hasattr(ts, "LANG") and ext in ts.LANG:
                    items = extract_ts(fpath, ts.LANG[ext], raw, lang, rel)
                else:
                    items = extract_regex(fpath, content, lang, rel)

                results.extend(items)

                # Collect global variables and code outside functions
                func_lines = {ln for item in items for ln in range(item["start_line"], item["end_line"] + 1)}
                global_lines = [
                    line for i, line in enumerate(content.splitlines(), 1)
                    if i not in func_lines and line.strip() and not line.strip().startswith("#")
                ]

                if global_lines:
                    body = "\n".join(global_lines)
                    results.append({
                        "file":       rel,
                        "function":   "[global]",
                        "signature":  f"[global scope of {fname}]",
                        "context":    "",
                        "body":       body[:2000] + (" ..." if len(body) > 2000 else ""),
                        "language":   lang,
                        "kind":       "global",
                        "start_line": 1,
                        "end_line":   content.count("\n") + 1,
                    })

            except Exception:
                pass

    return results
