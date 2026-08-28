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

# Extract functions using tree-sitter API
def extract_func(fpath: str, code: bytes, lang: str, rel: str) -> list:
    ts = load_ts()
    if not ts: return []
    
    ext = os.path.splitext(fpath)[1].lower()
    
    from tree_sitter import Parser, Language
    lang_obj = ts.LANG.get(ext)
    if not lang_obj: return []
    parser = Parser(Language(lang_obj))
    tree = parser.parse(code)
    
    func_nodes = ts.get_func_nodes(tree.root_node, ext, code)
    
    results = []
    seen = set()
    
    for node, name in func_nodes.items():
        if name in seen: continue
        seen.add(name)

        sig_lines = code[node.start_byte:node.end_byte].decode("utf-8", errors="ignore").splitlines()
        sig  = sig_lines[0].strip() if sig_lines else name
        
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

# Extract global variables and code outside functions
def extract_global(fpath: str, code: bytes, lang: str, rel: str, func_items: list) -> list:
    func_lines = {ln for item in func_items for ln in range(item["start_line"], item["end_line"] + 1)}
    content = code.decode("utf-8", errors="replace")
    
    global_lines = [
        line for i, line in enumerate(content.splitlines(), 1)
        if i not in func_lines and line.strip() and not line.strip().startswith("#") and not line.strip().startswith("//")
    ]

    if global_lines:
        body = "\n".join(global_lines)
        fname = os.path.basename(fpath)
        return [{
            "file":       rel,
            "function":   "[global]",
            "signature":  f"[global scope of {fname}]",
            "context":    "",
            "body":       body[:2000] + (" ..." if len(body) > 2000 else ""),
            "language":   lang,
            "kind":       "global",
            "start_line": 1,
            "end_line":   content.count("\n") + 1,
        }]
    return []

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
                    items = extract_func(fpath, raw, lang, rel)
                else:
                    items = extract_regex(fpath, content, lang, rel)
                    
                globals = extract_global(fpath, raw, lang, rel, items)
                
                results.extend(items)
                results.extend(globals)

            except Exception:
                pass

    return results
