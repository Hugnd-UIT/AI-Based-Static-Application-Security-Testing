import os
import re
import importlib
from pathlib import Path

def init_sitter():
    import importlib.util
    from pathlib import Path
    ts_path = Path(__file__).parent.parent / "audit" / "tree-sitter.py"
    spec = importlib.util.spec_from_file_location("ts_module", str(ts_path.resolve()))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    return mod

def resolve_path(target_dir: str, rel_path: str) -> Path:
    abs_path = (Path(target_dir) / rel_path).resolve()

    if not str(abs_path).startswith(str(Path(target_dir).resolve())):
        raise ValueError(f"Path traversal attempt: {rel_path}")

    return abs_path

def read_file(tool_args: dict, target_dir: str, ts_module=None) -> str:
    rel_path = tool_args.get("path", "")

    if not rel_path:

        return "[ERROR] read_file: 'path' is required."

    start_line = int(tool_args.get("start_line", 1))
    end_line = int(tool_args.get("end_line", start_line + 79))

    try:
        abs_path = resolve_path(target_dir, rel_path)
        with open(abs_path, "r", encoding="utf-8", errors="replace") as file_handle:
            file_lines = file_handle.readlines()

        start_idx = max(0, start_line - 1)
        end_idx = min(len(file_lines), end_line)
        chunk_text = "".join(file_lines[start_idx:end_idx])

        file_header = f"[FILE: {rel_path}  lines {start_line}-{end_line}]\n"

        return file_header + chunk_text if chunk_text else f"[EMPTY or out-of-range: {rel_path}]"

    except FileNotFoundError:

        return f"[ERROR] File not found: {rel_path}"

    except Exception as read_err:

        return f"[ERROR] read_file({rel_path}): {read_err}"

def trace_variable(tool_args: dict, target_dir: str, ts_module=None) -> str:
    var_name = tool_args.get("var_name", "")
    file_path = tool_args.get("file_path", "")

    if not var_name or not file_path:

        return "[ERROR] trace_variable: 'var_name' and 'file_path' are required."

    try:
        tree_sitter = ts_module or init_sitter()
        abs_path = resolve_path(target_dir, file_path)
        trace_result = tree_sitter.resolve_aliases_chain(str(abs_path), var_name)

        if trace_result:

            return f"[ALIAS CHAIN for '{var_name}' in {file_path}]\n{trace_result}"

        return f"[NO ALIAS] '{var_name}' has no detected alias chain defined inline or not found."

    except AttributeError:

        return trace_fallback(var_name, file_path, target_dir)

    except Exception as trace_err:

        return f"[ERROR] trace_variable({var_name}): {trace_err}"

def trace_fallback(var_name: str, file_path: str, target_dir: str) -> str:
    try:
        abs_path = resolve_path(target_dir, file_path)
        with open(abs_path, "r", encoding="utf-8", errors="replace") as file_handle:
            file_lines = file_handle.readlines()

        search_pattern = re.compile(
            rf"\b{re.escape(var_name)}\b\s*=\s*.+|"
            rf".+\b{re.escape(var_name)}\b"
        )
        match_hits = []

        for line_num, line_text in enumerate(file_lines, 1):

            if search_pattern.search(line_text):
                match_hits.append(f"  line {line_num:4d}: {line_text.rstrip()}")

            if len(match_hits) >= 30:
                match_hits.append("  ... (truncated)")
                break

        if match_hits:

            return f"[VARIABLE TRACE for '{var_name}' in {file_path}]\n" + "\n".join(match_hits)

        return f"[NOT FOUND] '{var_name}' not referenced in {file_path}"

    except Exception as fallback_err:

        return f"[ERROR] trace_variable fallback: {fallback_err}"

def find_function(tool_args: dict, target_dir: str, ts_module=None) -> str:
    func_name = tool_args.get("function_name", "")

    if not func_name:

        return "[ERROR] find_function: 'function_name' is required."

    try:
        tree_sitter = ts_module or init_sitter()
        func_source = tree_sitter.get_code(target_dir, func_name)

        return func_source or f"[NOT FOUND] Function '{func_name}' not found in the repository."

    except Exception as find_err:

        return f"[ERROR] find_function({func_name}): {find_err}"

def find_callers(tool_args: dict, target_dir: str, ts_module=None) -> str:
    func_name = tool_args.get("function_name", "")

    if not func_name:

        return "[ERROR] find_callers: 'function_name' is required."

    try:
        tree_sitter = ts_module or init_sitter()

        caller_results = []
        skip_dirs = {".git", "node_modules", "vendor", ".venv", "__pycache__"}

        for root_dir, sub_dirs, file_list in os.walk(target_dir):
            sub_dirs[:] = [d for d in sub_dirs if d not in skip_dirs]

            for file_name in file_list:
                file_path = Path(root_dir) / file_name
                file_ext = file_path.suffix.lower()

                if file_ext not in tree_sitter.LANG:
                    continue

                try:
                    with open(file_path, "rb") as file_handle:
                        source_code = file_handle.read()
                    ts_parser = tree_sitter.Parser(tree_sitter.Language(tree_sitter.LANG[file_ext]))
                    parsed_tree = ts_parser.parse(source_code)
                    caller_nodes = tree_sitter.find_callers(parsed_tree.root_node, func_name, source_code)

                    for caller_node in caller_nodes:
                        caller_code = source_code[caller_node.start_byte:caller_node.end_byte].decode("utf-8", errors="ignore")
                        rel_path = str(file_path.relative_to(target_dir))
                        caller_results.append(f"[CALLER IN {rel_path}  line {caller_node.start_point[0]+1}]\n{caller_code[:600]}")

                except Exception:
                    pass

        if caller_results:

            return "\n\n".join(caller_results)

        return f"[NOT FOUND] No callers of '{func_name}' found."

    except Exception as caller_err:

        return f"[ERROR] find_callers({func_name}): {caller_err}"

def search_pattern(tool_args: dict, target_dir: str, ts_module=None) -> str:
    search_query = tool_args.get("pattern", "")
    file_ext = tool_args.get("file_ext", None)

    if not search_query:

        return "[ERROR] search_pattern: 'pattern' is required."

    try:
        regex_obj = re.compile(search_query)

    except re.error:
        regex_obj = re.compile(re.escape(search_query))

    match_results = []
    skip_dirs = {".git", "node_modules", "vendor", ".venv", "__pycache__"}

    try:

        for root_dir, sub_dirs, file_list in os.walk(target_dir):
            sub_dirs[:] = [d for d in sub_dirs if d not in skip_dirs]

            for file_name in file_list:

                if file_ext and not file_name.endswith(file_ext):
                    continue

                file_path = Path(root_dir) / file_name

                try:
                    with open(file_path, "r", encoding="utf-8", errors="replace") as file_handle:

                        for line_num, line_text in enumerate(file_handle, 1):

                            if regex_obj.search(line_text):
                                rel_path = str(file_path.relative_to(target_dir))
                                match_results.append(f"  {rel_path}:{line_num}: {line_text.rstrip()}")

                                if len(match_results) >= 50:
                                    break

                except Exception:
                    pass

            if len(match_results) >= 50:
                match_results.append("  ... (results truncated at 50)")
                break

        if match_results:

            return f"[PATTERN '{search_query}']\n" + "\n".join(match_results)

        return f"[NO MATCH] Pattern '{search_query}' not found."

    except Exception as search_err:

        return f"[ERROR] search_pattern: {search_err}"

def submit_verdict(tool_args: dict, target_dir: str, ts_module=None) -> dict:
    return tool_args

TOOL_MAP = {
    "read_file":       read_file,
    "trace_variable":  trace_variable,
    "find_function":   find_function,
    "find_callers":    find_callers,
    "search_pattern":  search_pattern,
    "submit_verdict":  submit_verdict,
}

def execute_tool(tool_name: str, tool_args: dict, target_dir: str, ts_module=None):
    if tool_name not in TOOL_MAP:

        return f"[ERROR] Unknown tool: '{tool_name}'. Available: {list(TOOL_MAP)}"

    return TOOL_MAP[tool_name](tool_args, target_dir, ts_module)

