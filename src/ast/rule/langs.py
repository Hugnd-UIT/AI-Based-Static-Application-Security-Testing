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
