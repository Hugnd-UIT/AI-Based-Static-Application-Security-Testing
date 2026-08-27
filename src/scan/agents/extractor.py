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

SKIP_DIRS = {'node_modules', 'vendor', 'target', 'build', 'dist', '.git', '__pycache__', 'venv', '.venv', 'bin', 'obj'}

def _load_ts():
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

def _is_func_node(kind: str) -> bool:
    return (
        kind in (
            "function_definition", "function_declaration",
            "method_declaration", "method_definition",
            "function_item", "func_declaration",
        )
        or "function" in kind
        or "method" in kind
    )

def _get_name(node, code: bytes) -> str:
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

def _extract_ts(fpath: str, lang_obj, code: bytes, lang: str, rel: str) -> list:
    from tree_sitter import Parser, Language
    parser = Parser(Language(lang_obj))
    tree = parser.parse(code)
    results = []
    seen = set()

    def visit(node):
        kind = node.type.lower()

        if _is_func_node(kind):
            name = _get_name(node, code)
            if name and name not in seen:
                seen.add(name)
                sig_bytes = code[node.start_byte:node.end_byte]
                sig_lines = sig_bytes.decode("utf-8", errors="ignore").splitlines()
                sig = sig_lines[0].strip() if sig_lines else name
                body = "\n".join(sig_lines[1:min(11, len(sig_lines))])
                results.append({
                    "file":      rel,
                    "function":  name,
                    "signature": sig,
                    "context":   "",
                    "body":      body,
                    "language":  lang,
                    "kind":      "definition",
                    "start_line": node.start_point[0] + 1,
                    "end_line":   node.end_point[0] + 1,
                })

        for ch in node.children:
            visit(ch)

    visit(tree.root_node)
    return results

def _extract_regex(fpath: str, content: str, lang: str, rel: str) -> list:
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
            body = "\n".join(content[b:b + 400].split("\n")[:10])

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

def extract_functions(target_dir: str) -> list:
    ts = _load_ts()
    results = []

    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

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
                    items = _extract_ts(fpath, ts.LANG[ext], raw, lang, rel)
                else:
                    items = _extract_regex(fpath, content, lang, rel)

                results.extend(items)

            except Exception:
                pass

    return results