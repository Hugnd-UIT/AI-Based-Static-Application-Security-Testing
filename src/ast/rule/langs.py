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
import tree_sitter_rust as ts_rust
import tree_sitter_scala as ts_scala
from tree_sitter import Language, Parser

LANG = {
    ".py": ts_py.language(),
    ".js": ts_js.language(),
    ".jsx": ts_js.language(),
    ".mjs": ts_js.language(),
    ".cjs": ts_js.language(),
    ".ts": ts_ts.language_typescript(),
    ".tsx": ts_ts.language_tsx(),
    ".php": ts_php.language_php(),
    ".java": ts_java.language(),
    ".go": ts_go.language(),
    ".rb": ts_ruby.language(),
    ".cs": ts_cs.language(),
    ".c": ts_c.language(),
    ".h": ts_c.language(),
    ".cpp": ts_cpp.language(),
    ".cc": ts_cpp.language(),
    ".cxx": ts_cpp.language(),
    ".hpp": ts_cpp.language(),
    ".rs": ts_rust.language(),
    ".scala": ts_scala.language(),
}
