import os
import re
import json
import importlib
from pathlib import Path

TOOLS = {
    "read_file",
    "trace_variable",
    "find_function",
    "find_callers",
    "search_pattern",
    "submit_verdict",
}

# Initialize tree-sitter
def start_sitter():
    import importlib.util
    from pathlib import Path
    path = Path(__file__).parent.parent / "ast" / "tree-sitter.py"
    spec = importlib.util.spec_from_file_location("module", str(path.resolve()))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    return mod

# Path resolution function
def resolve_path(target: str, rel: str) -> Path:
    root = Path(target).resolve()
    path = (root / rel).resolve()

    # Prevent path traversal
    if path != root and root not in path.parents:
        raise ValueError(f"Path traversal attempt: {rel}")

    return path

# File reading tool
def read_file(args: dict, target: str, module=None) -> str:
    rel = args.get("path", "")

    # Check path
    if not rel:
        return "[ERROR] 'path' is required."

    start = int(args.get("start_line", 1))
    end = int(args.get("end_line", start + 79))

    try:
        path = resolve_path(target, rel)
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()

        head = max(0, start - 1)
        tail = min(len(lines), end)
        chunk = "".join(lines[head:tail])

        header = f"[FILE: {rel}  lines {start}-{end}]\n"

        return header + chunk if chunk else f"[EMPTY or OUT-OF-RANGE: {rel}]"

    except FileNotFoundError:
        return f"[ERROR] File not found: {rel}"

    except Exception as err:
        return f"[ERROR] Read file {rel}: {err}"

# Variable tracing tool - AST
def trace_variable(args: dict, target: str, module=None) -> str:
    var = args.get("var_name", "")
    file = args.get("file_path", "")

    if not var or not file:
        return "[ERROR] 'var_name' and 'file_path' are required."

    try:
        sitter = module or start_sitter()
        path = resolve_path(target, file)
        
        # Use AST to analyze variable
        trace = sitter.resolve_aliases_chain(str(path), var)

        if trace:
            return f"[ALIAS CHAIN for '{var}' in {file}]\n{trace}"

        return f"[NO ALIAS] '{var}' has no detected alias chain defined inline or not found."

    # Use Regex if AST fails
    except AttributeError:
        return trace_fallback(var, file, target)

    except Exception as err:
        return f"[ERROR] trace_variable({var}): {err}"

# Variable tracing tool - Regex
def trace_fallback(var: str, file: str, target: str) -> str:
    try:
        path = resolve_path(target, file)
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()

        pattern = re.compile(
            rf"\b{re.escape(var)}\b\s*=\s*.+|"
            rf".+\b{re.escape(var)}\b"
        )
        hits = []

        for num, text in enumerate(lines, 1):
            if pattern.search(text):
                hits.append(f"  line {num:4d}: {text.rstrip()}")

            # Limit to 150 results
            if len(hits) >= 150:
                hits.append("...")
                break

        if hits:
            return f"[VARIABLE TRACE for '{var}' in {file}]\n" + "\n".join(hits)

        return f"[NOT FOUND] '{var}' not referenced in {file}"

    except Exception as err:
        return f"[ERROR] trace_variable fallback: {err}"

# Function finding tool
def find_function(args: dict, target: str, module=None) -> str:
    func = args.get("function_name", "")

    if not func:
        return "[ERROR] 'function_name' is required."

    try:
        sitter = module or start_sitter()
        source = sitter.get_code(target, func)

        return source or f"[NOT FOUND] Function '{func}' not found in the repository."

    except Exception as err:
        return f"[ERROR] find_function({func}): {err}"

# Caller finding tool
def find_callers(args: dict, target: str, module=None) -> str:
    func = args.get("function_name", "")

    if not func:
        return "[ERROR] 'function_name' is required."

    try:
        sitter = module or start_sitter()
        callers = []
        skip = {".git", "node_modules", "vendor", ".venv", "__pycache__"}

        # Walk entire directory tree
        for root, dirs, files in os.walk(target):
            dirs[:] = [d for d in dirs if d not in skip]

            for name in files:
                path = Path(root) / name
                ext = path.suffix.lower()

                # Skip unsupported files
                if ext not in sitter.LANG:
                    continue

                try:
                    with open(path, "rb") as f:
                        code = f.read()
                    
                    parser = sitter.get_parser(ext)
                    tree = parser.parse(code)
                    nodes = sitter.find_callers(tree.root_node, func, code)

                    for node in nodes:
                        snippet = code[node.start_byte:node.end_byte].decode("utf-8", errors="ignore")
                        rel = str(path.relative_to(target))
                        callers.append(f"[CALLER IN {rel}  line {node.start_point[0]+1}]\n{snippet[:600]}")

                except Exception:
                    pass

        if callers:
            return "\n\n".join(callers)

        return f"[NOT FOUND] No callers of '{func}' found."

    except Exception as err:
        return f"[ERROR] find_callers({func}): {err}"

# Pattern search tool
def search_pattern(args: dict, target: str, module=None) -> str:
    query = args.get("pattern", "")
    ext = args.get("file_ext", None)

    if not query:
        return "[ERROR] search_pattern: 'pattern' is required."

    # Check regex, fallback to plain string search if invalid
    try:
        regex = re.compile(query)
    except re.error:
        regex = re.compile(re.escape(query))

    matches = []
    skip = {".git", "node_modules", "vendor", ".venv", "__pycache__"}

    try:
        for root, dirs, files in os.walk(target):
            dirs[:] = [d for d in dirs if d not in skip]

            for name in files:
                
                # Skip if file extension filter is active
                if ext and not name.endswith(ext):
                    continue

                path = Path(root) / name

                try:
                    with open(path, "r", encoding="utf-8", errors="replace") as f:
                        for num, text in enumerate(f, 1):
                            
                            # If line contains keyword
                            if regex.search(text):
                                rel = str(path.relative_to(target))
                                matches.append(f"  {rel}:{num}: {text.rstrip()}")

                                # Limit to 150 results
                                if len(matches) >= 150:
                                    break

                except Exception:
                    pass

            if len(matches) >= 150:
                matches.append("  ... (results truncated at 150)")
                break

        if matches:
            return f"[PATTERN '{query}']\n" + "\n".join(matches)

        return f"[NO MATCH] Pattern '{query}' not found."

    except Exception as err:
        return f"[ERROR] search_pattern: {err}"

# Submit verdict tool
def submit_verdict(args: dict, target: str, module=None) -> dict:
    return args

# Cache rslts
memory = {}
LIMIT = 512

# Clear cache
def reset_memory():
    memory.clear()

# Execute tool function
def execute_tool(name: str, args: dict, target: str, module=None):
    if name not in TOOLS:
        return f"[ERROR] Unknown tool: '{name}'. Available: {list(TOOLS)}"

    func = globals().get(name)

    if name == "submit_verdict":
        return func(args, target, module)

    key = (target, name, json.dumps(args, sort_keys=True, default=str))

    if key in memory:
        return memory[key]

    result = func(args, target, module)

    # Cache successful actions
    if isinstance(result, str) and not result.startswith("[ERROR]") and len(memory) < LIMIT:
        memory[key] = result

    return result