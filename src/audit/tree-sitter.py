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
