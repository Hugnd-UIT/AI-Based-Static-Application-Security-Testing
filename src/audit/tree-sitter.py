import os
from pathlib import Path

import tree_sitter_python
import tree_sitter_javascript
import tree_sitter_typescript
import tree_sitter_php
import tree_sitter_java
import tree_sitter_go
import tree_sitter_ruby
import tree_sitter_c_sharp
import tree_sitter_c
import tree_sitter_cpp
from tree_sitter import Language, Parser

LANG = {
    ".py": tree_sitter_python.language(),
    ".js": tree_sitter_javascript.language(),
    ".ts": tree_sitter_typescript.language_typescript(),
    ".php": tree_sitter_php.language_php(),
    ".java": tree_sitter_java.language(),
    ".go": tree_sitter_go.language(),
    ".rb": tree_sitter_ruby.language(),
    ".cs": tree_sitter_c_sharp.language(),
    ".c": tree_sitter_c.language(),
    ".cpp": tree_sitter_cpp.language(),
}

SOURCES = [
    "request.args", "request.form", "request.json", "request.data",
    "request.values", "request.cookies", "request.headers",
    "request.GET", "request.POST", "request.body", "request.META",
    "req.query", "req.body", "req.params", "req.headers", "req.cookies",
    "ctx.query", "ctx.request",
    "$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_SERVER",
    "params[", "request.env",
    "getParameter", "getHeader", "getCookies",
    "Request.Query", "Request.Form", "Request.Headers",
]

SINKS = [
    "execute", "query", "exec", "rawQuery", "ExecuteNonQuery",
    "ExecuteReader", "executeQuery", "executeUpdate",
    "system", "popen", "shell_exec", "eval", "exec",
    "subprocess.run", "subprocess.Popen", "subprocess.call",
    "render_template_string", "pickle.loads", "yaml.load",
    "os.system", "os.popen",
    "strcpy", "sprintf", "gets",
]

def extract_code(source_code: bytes, ast_node) -> str:
    return source_code[ast_node.start_byte : ast_node.end_byte].decode("utf-8")

def get_node_name(ast_node, source_code: bytes) -> str:
    for child_node in ast_node.children:
        if child_node.type == "identifier" or child_node.type == "name":
            return extract_code(source_code, child_node)
    return None

def find_func(ast_node, start_line: int, end_line: int):
    start_idx = start_line - 1
    end_idx = end_line - 1

    match_node = None
    context_groups = []

    def traverse_tree(curr_node):
        nonlocal match_node

        if curr_node.start_point[0] <= start_idx and curr_node.end_point[0] >= end_idx:
            node_kind = curr_node.type.lower()

            if "function" in node_kind or "method" in node_kind or "declaration" in node_kind:
                match_node = curr_node
            elif (
                "if_statement" in node_kind
                or "try_statement" in node_kind
                or "for_statement" in node_kind
                or "while_statement" in node_kind
            ):
                if node_kind not in context_groups:
                    context_groups.append(node_kind)

            for child_node in curr_node.children:
                traverse_tree(child_node)

    traverse_tree(ast_node)
    return match_node, context_groups

def find_callers(root_node, target_name: str, source_code: bytes):
    caller_list = []

    def traverse_callers(curr_node, func_node):
        node_kind = curr_node.type.lower()

        if "function" in node_kind or "method" in node_kind or "declaration" in node_kind:
            func_node = curr_node

        if "call" in node_kind or "invocation" in node_kind:
            for child_node in curr_node.children:
                if child_node.type == "identifier":
                    node_val = extract_code(source_code, child_node)

                    if node_val == target_name and func_node:
                        if func_node not in caller_list:
                            caller_list.append(func_node)

        for child_node in curr_node.children:
            traverse_callers(child_node, func_node)

    traverse_callers(root_node, None)
    return caller_list

def find_global_callers(target_dir: str, target_name: str, file_ext: str, ts_parser: Parser):
    caller_context = ""

    if not target_dir or not Path(target_dir).exists():
        return ""

    for root_dir, _, file_list in os.walk(target_dir):
        if ".git" in root_dir or "node_modules" in root_dir or "vendor" in root_dir:
            continue

        for file_name in file_list:
            if not file_name.endswith(file_ext):
                continue

            file_path = Path(root_dir) / file_name

            try:
                with open(file_path, "rb") as file_obj:
                    file_content = file_obj.read()

                parsed_tree = ts_parser.parse(file_content)
                caller_list = find_callers(parsed_tree.root_node, target_name, file_content)

                for caller_node in caller_list:
                    caller_code = extract_code(file_content, caller_node)
                    caller_context += f"[CALLER IN {file_name}]\n{caller_code}\n\n"
            except Exception:
                pass

    return caller_context


def is_func(node_kind: str) -> bool:
    return (
        node_kind in (
            "function_definition", "function_declaration",
            "method_declaration", "method_definition",
            "function_item", "func_declaration",
        )
        or "function" in node_kind
        or "method" in node_kind
    )

def has_source(file_content: bytes, curr_node) -> bool:
    try:
        node_text = file_content[curr_node.start_byte:curr_node.end_byte].decode("utf-8", errors="ignore")
        return any(source_str in node_text for source_str in SOURCES)
    except Exception:
        return False

def has_sink(file_content: bytes, curr_node) -> bool:
    try:
        node_text = file_content[curr_node.start_byte:curr_node.end_byte].decode("utf-8", errors="ignore")
        return any(sink_str in node_text for sink_str in SINKS)
    except Exception:
        return False

def get_tainted_funcs(target_dir: str) -> dict:
    tainted_funcs = {}

    for root_dir, sub_dirs, file_list in os.walk(target_dir):
        sub_dirs[:] = [d for d in sub_dirs if d not in {".git", "node_modules", "vendor", ".venv", "__pycache__"}]

        for file_name in file_list:
            file_ext = Path(file_name).suffix.lower()
            if file_ext not in LANG:
                continue

            file_path = Path(root_dir) / file_name

            try:
                with open(file_path, "rb") as file_obj:
                    file_content = file_obj.read()

                ts_parser = Parser(Language(LANG[file_ext]))
                parsed_tree = ts_parser.parse(file_content)

                def traverse_tree(curr_node):
                    node_kind = curr_node.type.lower()
                    if is_func(node_kind) and has_source(file_content, curr_node):
                        func_name = get_node_name(curr_node, file_content)
                        func_code = file_content[curr_node.start_byte:curr_node.end_byte].decode("utf-8", errors="ignore")
                        if func_name and func_name not in tainted_funcs:
                            tainted_funcs[func_name] = {"file": str(file_path), "code": func_code[:800]}
                    for child_node in curr_node.children:
                        traverse_tree(child_node)

                traverse_tree(parsed_tree.root_node)

            except Exception:
                pass

    return tainted_funcs

def find_cross_sinks(target_dir: str, tainted_funcs: dict) -> str:
    if not tainted_funcs:
        return ""

    cross_paths = []
    tainted_names = set(tainted_funcs.keys())

    for root_dir, sub_dirs, file_list in os.walk(target_dir):
        sub_dirs[:] = [d for d in sub_dirs if d not in {".git", "node_modules", "vendor", ".venv", "__pycache__"}]

        for file_name in file_list:
            file_ext = Path(file_name).suffix.lower()
            if file_ext not in LANG:
                continue

            file_path = Path(root_dir) / file_name

            try:
                with open(file_path, "rb") as file_obj:
                    file_content = file_obj.read()

                file_text = file_content.decode("utf-8", errors="ignore")
                called_tainted = [fn for fn in tainted_names if fn in file_text]

                if not called_tainted:
                    continue

                ts_parser = Parser(Language(LANG[file_ext]))
                parsed_tree = ts_parser.parse(file_content)

                def scan_taint(curr_node, parent_func_node=None):
                    node_kind = curr_node.type.lower()

                    if is_func(node_kind):
                        parent_func_node = curr_node

                    if ("call" in node_kind or "invocation" in node_kind) and parent_func_node:
                        call_ident = None
                        for child_node in curr_node.children:
                            if child_node.type == "identifier":
                                call_ident = child_node
                                break
                            elif child_node.type in ("attribute", "member_expression"):
                                for gchild_node in child_node.children:
                                    if gchild_node.type == "property_identifier" or gchild_node.type == "identifier":
                                        call_ident = gchild_node
                                        
                        if call_ident:
                            func_called = file_content[call_ident.start_byte:call_ident.end_byte].decode("utf-8", errors="ignore")
                            if func_called in called_tainted and has_sink(file_content, parent_func_node):
                                origin_info = tainted_funcs.get(func_called, {})
                                parent_text = file_content[parent_func_node.start_byte:parent_func_node.end_byte].decode("utf-8", errors="ignore")
                                path_entry = (
                                    f"[CROSS-FILE TAINT PATH DETECTED]\n"
                                    f"  Tainted Source : {func_called}() in {origin_info.get('file', 'unknown')}\n"
                                    f"  Propagates to  : {file_name} (line {curr_node.start_point[0] + 1})\n"
                                    f"  Caller function:\n{parent_text[:600]}\n"
                                    f"  Origin function:\n{origin_info.get('code', '')[:400]}\n"
                                )
                                if path_entry not in cross_paths:
                                    cross_paths.append(path_entry)

                    for child_node in curr_node.children:
                        scan_taint(child_node, parent_func_node)

                scan_taint(parsed_tree.root_node)

            except Exception:
                pass

    return "\n".join(cross_paths)

def build_context(target_dir: str) -> str:
    if not target_dir or not Path(target_dir).exists():
        return ""

    tainted_funcs = get_tainted_funcs(target_dir)
    if not tainted_funcs:
        return ""

    return find_cross_sinks(target_dir, tainted_funcs)


def extract_context(
    path_str: str,
    start_line: int,
    end_line: int,
    target_dir: str = None,
    max_depth: int = 2,
) -> str:
    file_path = Path(path_str)

    if not file_path.exists():
        return ""

    file_ext = file_path.suffix.lower()

    if file_ext not in LANG:
        return extract_chunk(file_path, start_line, end_line)

    try:
        ts_parser = Parser()
        ts_lang = Language(LANG[file_ext])

        ts_parser.set_language(ts_lang)

        with open(file_path, "rb") as file_obj:
            source_code = file_obj.read()

        parsed_tree = ts_parser.parse(source_code)
        sink_node, context_groups = find_func(parsed_tree.root_node, start_line, end_line)

        if not sink_node:
            return extract_chunk(file_path, start_line, end_line)

        sink_code = extract_code(source_code, sink_node)

        if context_groups:
            meta_text = f"// Vulnerability is nested inside: {', '.join(context_groups)}\n"
            sink_code = meta_text + sink_code

        sink_name = get_node_name(sink_node, source_code)

        if not sink_name or max_depth < 1:
            return f"[SINK]\n{sink_code}"

        caller_context = ""

        if target_dir:
            caller_context += find_global_callers(target_dir, sink_name, file_ext, ts_parser)
        else:
            caller_list = find_callers(parsed_tree.root_node, sink_name, source_code)

            for caller_node in caller_list:
                caller_code = extract_code(source_code, caller_node)
                caller_context += f"[CALLER]\n{caller_code}\n\n"

        caller_context += f"[SINK]\n{sink_code}"
        return caller_context

    except Exception:
        return extract_chunk(file_path, start_line, end_line)

def extract_chunk(file_path: Path, start_line: int, end_line: int, padding_lines: int = 15) -> str:
    with open(file_path, "r", encoding="utf-8") as file_obj:
        file_lines = file_obj.readlines()

    start_idx = max(0, start_line - 1 - padding_lines)
    end_idx = min(len(file_lines), end_line + padding_lines)

    return "".join(file_lines[start_idx:end_idx])

def get_func_code(target_dir: str, target_func: str) -> str:
    for root_dir, sub_dirs, file_list in os.walk(target_dir):
        sub_dirs[:] = [d for d in sub_dirs if d not in {".git", "node_modules", "vendor", ".venv", "__pycache__"}]
        for file_name in file_list:
            file_ext = Path(file_name).suffix.lower()
            if file_ext not in LANG: continue
            file_path = Path(root_dir) / file_name
            try:
                with open(file_path, "rb") as file_obj:
                    file_content = file_obj.read()
                
                if target_func.encode("utf-8") not in file_content:
                    continue

                ts_parser = Parser(Language(LANG[file_ext]))
                parsed_tree = ts_parser.parse(file_content)

                match_code = ""
                def find_def(curr_node):
                    nonlocal match_code
                    if match_code: return
                    node_kind = curr_node.type.lower()
                    if is_func(node_kind) and get_node_name(curr_node, file_content) == target_func:
                        match_code = file_content[curr_node.start_byte:curr_node.end_byte].decode("utf-8", errors="ignore")
                        return
                    for child_node in curr_node.children:
                        find_def(child_node)

                find_def(parsed_tree.root_node)
                if match_code:
                    return f"[IMPLEMENTATION OF {target_func}() IN {file_name}]\n{match_code}"
            except Exception:
                pass
    return f"// Function {target_func}() not found in the repository."

def resolve_aliases(file_path: str, var_name: str) -> str:
    import re

    dir_path = Path(file_path)
    if not dir_path.exists():
        return f"File not found: {file_path}"

    file_ext = dir_path.suffix.lower()

    if file_ext not in LANG:
        with open(dir_path, "r", encoding="utf-8", errors="replace") as file_handle:
            file_lines = file_handle.readlines()
        regex_pattern = re.compile(rf"\b{re.escape(var_name)}\b")
        match_hits = [(idx + 1, line_text.rstrip()) for idx, line_text in enumerate(file_lines) if regex_pattern.search(line_text)]
        if not match_hits:
            return ""
        return "\n".join(f"  line {line_num:4d}: {code_snippet}" for line_num, code_snippet in match_hits[:30])

    try:
        with open(dir_path, "rb") as file_handle:
            source_code = file_handle.read()

        ts_parser = Parser(Language(LANG[file_ext]))
        parsed_tree = ts_parser.parse(source_code)

        alias_chain = []
        var_bytes = var_name.encode("utf-8")

        def visit_node(curr_node):
            if curr_node.type in (
                "assignment", "augmented_assignment",
                "variable_declarator", "local_variable_declaration",
                "expression_statement",
            ):
                node_text = source_code[curr_node.start_byte:curr_node.end_byte]
                if var_bytes in node_text:
                    code_snippet = node_text.decode("utf-8", errors="ignore").strip()
                    alias_chain.append((curr_node.start_point[0] + 1, code_snippet[:120]))

            for child_node in curr_node.children:
                visit_node(child_node)

        visit_node(parsed_tree.root_node)

        if not alias_chain:
            return ""

        output_lines = [f"  line {line_num:4d}: {code_snippet}" for line_num, code_snippet in alias_chain]
        return "\n".join(output_lines)

    except Exception as parse_err:
        return f"[resolve_aliases error] {parse_err}"


def find_sanitizer_path(
    file_path: str,
    source_line: int,
    sink_line: int,
) -> str:
    import re

    dir_path = Path(file_path)
    if not dir_path.exists():
        return f"File not found: {file_path}"

    try:
        with open(dir_path, "r", encoding="utf-8", errors="replace") as file_handle:
            all_lines = file_handle.readlines()
    except Exception as read_err:
        return f"[find_sanitizer_path error] {read_err}"

    start_idx = max(0, source_line - 1)
    end_idx   = min(len(all_lines), sink_line)
    code_region = all_lines[start_idx:end_idx]

    match_hits = []
    for loop_idx, line_text in enumerate(code_region, start=source_line):
        for sanitizer_keyword in SANITIZERS:
            if re.search(sanitizer_keyword, line_text, re.IGNORECASE):
                stripped_text = line_text.strip()
                is_conditional = stripped_text.startswith(("if ", "elif ", "else:", "except", "try:"))
                indent_level = len(line_text) - len(line_text.lstrip())
                match_hits.append({
                    "line": loop_idx,
                    "text": stripped_text[:100],
                    "sanitizer": sanitizer_keyword,
                    "conditional": is_conditional,
                    "indent": indent_level,
                })
                break

    if not match_hits:
        return (
            f"[NO SANITIZER] No sanitizer detected between lines "
            f"{source_line}-{sink_line} in {dir_path.name}. "
            "Taint path is likely unguarded."
        )

    all_conditional = all(hit["conditional"] or hit["indent"] > 0 for hit in match_hits)

    summary_lines = [
        f"[SANITIZER ANALYSIS] {dir_path.name} lines {source_line}-{sink_line}:"
    ]
    for hit_item in match_hits:
        flag_type = "CONDITIONAL" if hit_item["conditional"] else "ON-PATH"
        summary_lines.append(f"  line {hit_item['line']:4d} [{flag_type}] {hit_item['text']}")

    if all_conditional:
        summary_lines.append(
            "  WARNING: All sanitizers are inside conditional branches "
            "- taint may reach sink on the unsanitized path."
        )
    else:
        summary_lines.append(
            "  At least one sanitizer is on the direct execution path."
        )

    return "\n".join(summary_lines)
