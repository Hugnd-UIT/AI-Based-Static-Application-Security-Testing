import os
from pathlib import Path

import tree_sitter_python as ts_py
import tree_sitter_javascript as ts_js
import tree_sitter_typescript as ts_ts
import tree_sitter_php as ts_php
import tree_sitter_java as ts_java
import tree_sitter_go as ts_go
import tree_sitter_ruby as ts_ruby
import tree_sitter_c_sharp as ts_cs
import tree_sitter_c as ts_c
import tree_sitter_cpp as ts_cpp
from tree_sitter import Language, Parser

LANG = {
    ".py": ts_py.language(),
    ".js": ts_js.language(),
    ".ts": ts_ts.language_typescript(),
    ".php": ts_php.language_php(),
    ".java": ts_java.language(),
    ".go": ts_go.language(),
    ".rb": ts_ruby.language(),
    ".cs": ts_cs.language(),
    ".c": ts_c.language(),
    ".cpp": ts_cpp.language(),
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
    # Python — CLI & Environment
    "os.environ", "sys.argv", "os.getenv",
    # Python — Network raw
    "socket.recv", "socket.recvfrom", "socket.recvmsg",
    # JavaScript — Event handlers
    "event.data", "event.target.value", "location.search",
    "location.hash", "location.href", "document.cookie",
    "window.name", "postMessage",
    # Java Spring
    "@PathVariable", "@RequestParam", "@RequestBody",
    "HttpServletRequest.getParameter", "HttpServletRequest.getHeader",
    "HttpServletRequest.getInputStream",
    # Go net/http & frameworks
    "r.URL.Query()", "r.FormValue", "r.PostFormValue",
    "r.Header.Get", "r.Body",
    "gin.Context.Query", "gin.Context.PostForm", "gin.Context.Param",
    "echo.Context.QueryParam", "echo.Context.FormValue",
    # PHP
    "$_FILES", "$_ENV", "$_SESSION",
    # Ruby on Rails
    "params[:", "request.params",
    # C# ASP.NET
    "Request.QueryString", "HttpContext.Request",
    # Serverless / Cloud Functions
    "event.body", "event.queryStringParameters",
    "event.pathParameters", "context.clientContext",
    # C/C++
    "getenv", "gets", "scanf", "fscanf", "recv", "recvfrom", "fread", "read", "std::cin", "getline",
    "fgets", "getchar", "readlink", "readdir",
]

SINKS = [
    "execute", "query", "exec", "rawQuery", "ExecuteNonQuery",
    "ExecuteReader", "executeQuery", "executeUpdate",
    "system", "popen", "shell_exec", "eval", "exec",
    "subprocess.run", "subprocess.Popen", "subprocess.call",
    "render_template_string", "pickle.loads", "yaml.load",
    "os.system", "os.popen",
    "strcpy", "sprintf", "gets",
    # C/C++ Memory & Command
    "memcpy", "strcat", "execl", "execv", "printf", "fopen", "unlink", "remove",
    # JavaScript DOM XSS
    "innerHTML", "outerHTML", "document.write", "document.writeln",
    "insertAdjacentHTML", "Function(",
    # JavaScript Command/File Injection  
    "child_process.exec", "child_process.spawn", "child_process.execSync",
    "fs.readFile", "fs.writeFile", "fs.appendFile", "fs.unlink",
    # JavaScript HTTP (reflected XSS/redirect)
    "res.send", "res.json", "res.end", "res.redirect", "res.location",
    # Python deserialization
    "pickle.load", "marshal.loads", "shelve.open",
    "jsonpickle.decode", "__reduce__",
    # Java RCE
    "Runtime.exec", "ProcessBuilder", "ScriptEngine.eval",
    "Class.forName", "Method.invoke",
    # Java JNDI (Log4Shell family)
    "InitialContext.lookup", "Context.lookup", "ldap://",
    # PHP
    "passthru", "preg_replace", "create_function", "assert",
    "include", "require", "include_once", "file_get_contents",
    # Go
    "os.Exec", "exec.Command", "exec.CommandContext",
    "ioutil.WriteFile", "os.WriteFile",
    # Ruby
    "open", "send", "`",
]

SANITIZERS = [
    # Python
    r"escape\(", r"sanitize\(", r"clean\(", r"validate\(",
    r"bleach\.clean", r"markupsafe", r"html\.escape",
    r"parameterized", r"prepared", r"cursor\.execute.*%s",
    # JS/TS
    r"DOMPurify\.sanitize", r"encodeURIComponent", r"escapeHTML",
    r"validator\.escape", r"xss\(",
    # Java
    r"PreparedStatement", r"escapeXml", r"ESAPI\.encoder",
    r"HtmlUtils\.htmlEscape",
    # PHP
    r"htmlspecialchars", r"htmlentities", r"filter_var",
    r"mysqli_real_escape_string", r"pg_escape_string",
    # C/C++
    r"strlcpy", r"strlcat", r"snprintf",
    # Go
    r"html\.EscapeString", r"template\.HTMLEscapeString",
    # Generic
    r"allowlist", r"whitelist", r"permit",
]

def extract_code(source_code: bytes, ast_node) -> str:
    return source_code[ast_node.start_byte : ast_node.end_byte].decode("utf-8")

def get_node(ast_node, source_code: bytes) -> str:
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

        if is_func(node_kind):
            func_node = curr_node

        if "call" in node_kind or "invocation" in node_kind:
            call_ident = None

            for child_node in curr_node.children:

                if child_node.type == "identifier":
                    call_ident = child_node
                    break

                elif child_node.type in ("attribute", "member_expression", "field_expression"):

                    for gchild_node in child_node.children:

                        if "identifier" in gchild_node.type:
                            call_ident = gchild_node
                            
            if call_ident:
                node_val = extract_code(source_code, call_ident)

                if node_val == target_name and func_node:

                    if func_node not in caller_list:
                        caller_list.append(func_node)

        for child_node in curr_node.children:
            traverse_callers(child_node, func_node)

    traverse_callers(root_node, None)

    return caller_list

def find_calls(target_dir: str, target_name: str, file_ext: str, ts_parser: Parser):
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

from src.audit.frameworks import check_entrypoint

def has_source(file_content: bytes, curr_node, file_ext: str = "") -> bool:
    try:
        node_text = file_content[curr_node.start_byte:curr_node.end_byte].decode("utf-8", errors="ignore")

        if any(source_str in node_text for source_str in SOURCES):

            return True

        if file_ext and check_entrypoint(node_text, file_ext):

            return True

        return False

    except Exception:

        return False

import re
SINKS_PATTERNS = [re.compile(r'\b' + re.escape(s) + r'\b') for s in SINKS]

def has_sink(file_content: bytes, curr_node) -> bool:
    try:
        node_text = file_content[curr_node.start_byte:curr_node.end_byte].decode("utf-8", errors="ignore")
        return any(p.search(node_text) for p in SINKS_PATTERNS)
    except Exception:
        return False

def get_all_calls(curr_node):
    calls = []
    def traverse(n):
        if "call" in n.type.lower() or "invocation" in n.type.lower():
            calls.append(n)
        for c in n.children:
            traverse(c)
    traverse(curr_node)
    return calls

def get_call_name(call_node, file_content):
    for child in call_node.children:
        if child.type == "identifier":
            return file_content[child.start_byte:child.end_byte].decode("utf-8", errors="ignore")
        elif child.type in ("attribute", "member_expression"):
            for gchild in child.children:
                if gchild.type in ("property_identifier", "identifier"):
                    return file_content[gchild.start_byte:gchild.end_byte].decode("utf-8", errors="ignore")
    return None

def scan_callees(func_node, file_content, target_dir, depth=0, max_depth=2):
    if depth > max_depth: return False
    if has_sink(file_content, func_node): return True
    
    for call_node in get_all_calls(func_node):
        callee_name = get_call_name(call_node, file_content)
        if callee_name:
            callee_code = get_code(target_dir, callee_name)
            if callee_code and not callee_code.startswith("//"):
                if any(p.search(callee_code) for p in SINKS_PATTERNS):
                    return True
    return False

def get_tainted(target_dir: str) -> dict:
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

                    if is_func(node_kind) and has_source(file_content, curr_node, file_ext):
                        func_name = get_node(curr_node, file_content)
                        func_code = file_content[curr_node.start_byte:curr_node.end_byte].decode("utf-8", errors="ignore")

                        if func_name and func_name not in tainted_funcs:
                            tainted_funcs[func_name] = {"file": str(file_path), "code": func_code[:800]}

                    for child_node in curr_node.children:
                        traverse_tree(child_node)

                traverse_tree(parsed_tree.root_node)

            except Exception:
                pass

    return tainted_funcs

def find_sinks(target_dir: str, tainted_funcs: dict) -> str:
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

                def scan_taint(curr_node, parent_node=None):
                    node_kind = curr_node.type.lower()

                    if is_func(node_kind):
                        parent_node = curr_node

                    if ("call" in node_kind or "invocation" in node_kind) and parent_node:
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

                            if func_called in called_tainted and scan_callees(parent_node, file_content, target_dir):
                                origin_info = tainted_funcs.get(func_called, {})
                                parent_text = file_content[parent_node.start_byte:parent_node.end_byte].decode("utf-8", errors="ignore")
                                path_entry = (
                                    f"[CROSS-FILE TAINT PATH DETECTED]\n"
                                    f"  Tainted Source : {func_called} in {origin_info.get('file', 'unknown')}\n"
                                    f"  Propagates to  : {file_name} (line {curr_node.start_point[0] + 1})\n"
                                    f"  Caller function:\n{parent_text[:600]}\n"
                                    f"  Origin function:\n{origin_info.get('code', '')[:400]}\n"
                                )

                                if path_entry not in cross_paths:
                                    cross_paths.append(path_entry)

                    for get_child in curr_node.children:
                        scan_taint(get_child, parent_node)

                scan_taint(parsed_tree.root_node)

            except Exception:
                pass

    return "\n".join(cross_paths)

from src.audit.frameworks import extract_events

def build_pubsub(target_dir: str) -> str:
    if not target_dir or not Path(target_dir).exists():

        return ""

    pubsub_info = []
    
    for root_dir, sub_dirs, file_list in os.walk(target_dir):
        sub_dirs[:] = [d for d in sub_dirs if d not in {".git", "node_modules", "vendor", ".venv", "__pycache__"}]

        for file_name in file_list:
            file_ext = Path(file_name).suffix.lower()

            if file_ext not in LANG: continue
            
            file_path = Path(root_dir) / file_name

            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    code_text = f.read()
                
                published, subscribed = extract_events(code_text, file_ext)

                if published:
                    pubsub_info.append(f"[EVENT PUBLISHER IN {file_name}]\nEmits: {', '.join(published)}")

                if subscribed:
                    pubsub_info.append(f"[EVENT SUBSCRIBER IN {file_name}]\nListens to: {', '.join(subscribed)}")

            except Exception:
                pass
                
    return "\n\n".join(pubsub_info)

def build_context(target_dir: str) -> str:
    if not target_dir or not Path(target_dir).exists():

        return ""

    tainted_funcs = get_tainted(target_dir)
    cross_sinks = find_sinks(target_dir, tainted_funcs) if tainted_funcs else ""
    pubsub_map = build_pubsub(target_dir)
    
    context = ""

    if cross_sinks:
        context += cross_sinks + "\n\n"

    if pubsub_map:
        context += "=== EVENT BUS / PUB-SUB ARCHITECTURE ===\n" + pubsub_map + "\n"
        
    return context


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
        ts_parser = Parser(Language(LANG[file_ext]))

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

        sink_name = get_node(sink_node, source_code)

        if not sink_name or max_depth < 1:

            return f"[SINK]\n{sink_code}"

        caller_context = ""

        if target_dir:
            caller_context += find_callers(target_dir, sink_name, file_ext, ts_parser)

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

_code_cache = {}

def get_code(target_dir: str, target_func: str) -> str:
    key = (target_dir, target_func)
    if key in _code_cache: return _code_cache[key]
    
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

                    if is_func(node_kind) and get_node(curr_node, file_content) == target_func:
                        match_code = file_content[curr_node.start_byte:curr_node.end_byte].decode("utf-8", errors="ignore")
                        return

                    for child_node in curr_node.children:
                        find_def(child_node)

                find_def(parsed_tree.root_node)

                if match_code:

                    _code_cache[key] = f"[IMPLEMENTATION OF {target_func} IN {file_name}]\n{match_code}"
                    return _code_cache[key]

            except Exception:
                pass

    _code_cache[key] = f"// Function {target_func} not found in the repository."
    return _code_cache[key]

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
                "declaration", "init_declarator", "assignment_expression",
                "update_expression",
                "short_var_declaration", "assignment_statement",
                "call_expression", "call", "return_statement"
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


def resolve_aliases_chain(file_path: str, var_name: str, max_hops: int = 5) -> str:
    import re
    visited = set()
    results = []
    
    def trace_one(current_var, hop):
        if hop > max_hops or current_var in visited:
            return
        visited.add(current_var)
        raw = resolve_aliases(file_path, current_var)
        if not raw or raw.startswith("File not found") or raw.startswith("[resolve_aliases error]"):
            return
        results.append(f"[HOP {hop}] {current_var}:\n{raw}")
        
        for line in raw.splitlines():
            rhs_match = re.search(r'=\s*([a-zA-Z_]\w*)\b', line)
            if rhs_match:
                upstream_var = rhs_match.group(1)
                if upstream_var not in visited:
                    trace_one(upstream_var, hop + 1)
    
    trace_one(var_name, 1)
    if not results:
        return ""
    return "\n\n".join(results)


def find_sanitizer(
    file_path: str,
    source_line: int,
    sink_line: int,
) -> str:
    import re

    dir_path = Path(file_path)
    file_ext = dir_path.suffix.lower()

    if not dir_path.exists():

        return f"File not found: {file_path}"

    try:
        with open(dir_path, "r", encoding="utf-8", errors="replace") as file_handle:
            all_lines = file_handle.readlines()

    except Exception as read_err:

        return f"[find_sanitizer error] {read_err}"

    start_idx = max(0, source_line - 1)
    end_idx   = min(len(all_lines), sink_line)
    code_region = all_lines[start_idx:end_idx]

    match_hits = []

    for loop_idx, line_text in enumerate(code_region, start=source_line):
        indent_level = len(line_text) - len(line_text.lstrip())
        
        # STRIP COMMENT BEFORE CHECKING
        comment_markers = {
            ".py": "#", ".js": "//", ".ts": "//", ".java": "//",
            ".go": "//", ".php": "//", ".cs": "//", ".c": "//", ".cpp": "//"
        }
        marker = comment_markers.get(file_ext, "#")
        idx = line_text.find(marker)
        if idx != -1:
            line_text = line_text[:idx]

        for sanitizer_keyword in SANITIZERS:

            if re.search(sanitizer_keyword, line_text, re.IGNORECASE):
                stripped_text = line_text.strip()
                is_conditional = stripped_text.startswith(("if ", "elif ", "else:", "except", "try:"))
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

