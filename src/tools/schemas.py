# Công cụ đọc file
READ_SCHEMA = {
    "type": "function",
    "function": {
        "name": "read_file",
        "description": "Read lines from a file in the workspace",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Relative file path",
                },
                "start_line": {
                    "type": "integer",
                    "description": "First line to read (1-indexed, inclusive) - Default: 1",
                },
                "end_line": {
                    "type": "integer",
                    "description": "Last line to read (1-indexed, inclusive) - Default: 80",
                },
            },
            "required": ["path"],
        },
    },
}

# Công cụ theo dõi biến
TRACE_SCHEMA = {
    "type": "function",
    "function": {
        "name": "trace_variable",
        "description": "Perform AST-based alias analysis on a variable inside a file to resolve the full alias chain - MUST be called on every variable appearing in the sink call before concluding",
        "parameters": {
            "type": "object",
            "properties": {
                "var_name": {
                    "type": "string",
                    "description": "The variable name to trace",
                },
                "file_path": {
                    "type": "string",
                    "description": "Relative file path that contains the variable",
                },
            },
            "required": ["var_name", "file_path"],
        },
    },
}

# Công cụ tìm hàm
FUNC_SCHEMA = {
    "type": "function",
    "function": {
        "name": "find_function",
        "description": "Search the codebase for the definition of a named function or method and return its full source code along with the file path - NEVER assume an unknown function is safe without calling this",
        "parameters": {
            "type": "object",
            "properties": {
                "function_name": {
                    "type": "string",
                    "description": "Name of the function or method to find",
                },
            },
            "required": ["function_name"],
        },
    },
}

# Công cụ tìm hàm gọi đến
CALLER_SCHEMA = {
    "type": "function",
    "function": {
        "name": "find_callers",
        "description": "Find every location in the codebase that calls a given function, returning each caller's source code and file path",
        "parameters": {
            "type": "object",
            "properties": {
                "function_name": {
                    "type": "string",
                    "description": "Name of the function whose callers you want to find",
                },
            },
            "required": ["function_name"],
        },
    },
}

# Công cụ tìm kiếm mẫu
SEARCH_SCHEMA = {
    "type": "function",
    "function": {
        "name": "search_pattern",
        "description": "Search the codebase for all occurrences of a text pattern (regex or literal) - Filter by file extension to limit scope",
        "parameters": {
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "The regex or literal string pattern to search for",
                },
                "file_ext": {
                    "type": "string",
                    "description": "File extension filter - Omit to search all files",
                },
            },
            "required": ["pattern"],
        },
    },
}

# Công cụ gửi kết quả
VERDICT_SCHEMA = {
    "type": "function",
    "function": {
        "name": "submit_verdict",
        "description": "Submit the final verdict to terminate the analysis loop - MUST be called with concrete evidence gathered from other tools",
        "parameters": {
            "type": "object",
            "properties": {
                "verdict": {
                    "type": "string",
                    "enum": ["VULNERABLE", "SAFE"],
                    "description": "'VULNERABLE' if an unbroken taint path to a dangerous sink is proven, 'SAFE' otherwise",
                },
                "severity": {
                    "type": "string",
                    "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                    "description": "Severity based on CVSS impact",
                },
                "confidence": {
                    "type": "integer",
                    "description": "Confidence score 0-100 - Must be >= 70 to submit VULNERABLE",
                },
                "cvss_estimate": {
                    "type": "number",
                    "description": "CVSS v3.1 base score estimate (0.0 - 10.0)",
                },
                "vuln_class": {
                    "type": "string",
                    "description": "CWE/vulnerability class",
                },
                "reasoning": {
                    "type": "string",
                    "description": "Chain-of-custody reasoning: source -> alias chain -> sink",
                },
                "attack_vector": {
                    "type": "string",
                    "description": "(Optional) A concrete attack example",
                },
                "source_identified": {"type": "boolean"},
                "source_variable": {"type": "string"},
                "sink_identified": {"type": "boolean"},
                "sink_function": {"type": "string"},
                "data_flow": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "step": {"type": "integer"},
                            "variable": {"type": "string"},
                            "operation": {"type": "string"},
                            "line": {"type": "integer"},
                        },
                    },
                },
                "hops_traced": {"type": "integer"},
                "cross_file": {"type": "boolean"},
                "flow_unbroken": {"type": "boolean"},
                "use_surrogate": {"type": "boolean"},
                "surrogate_function": {"type": "string"},
                "poc_type": {"type": "string"},
                "description": {"type": "string"},
                "payload": {"type": "string"},
                "explanation": {"type": "string"},
                "exploitable": {
                    "type": "boolean",
                    "description": "For PoC Verifier: True if the CVE can be exploited in the current context",
                },
                "extra_sinks": {
                    "type": "array",
                    "description": "For Sink Expander: List of new dangerous sink patterns discovered from the CVE context",
                    "items": {
                        "type": "object",
                        "properties": {
                            "pattern": {"type": "string", "description": "Regex or literal pattern to search for"},
                            "severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]},
                            "description": {"type": "string"}
                        }
                    }
                },
                "patches": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "file_path": {"type": "string"},
                            "old_code": {"type": "string"},
                            "new_code": {"type": "string"},
                        },
                    },
                },
            },
            "required": ["verdict"],
        },
    },
}

EXPAND_TOOLS = [SEARCH_SCHEMA, VERDICT_SCHEMA]
SCAN_TOOLS   = [READ_SCHEMA, TRACE_SCHEMA, FUNC_SCHEMA, CALLER_SCHEMA, VERDICT_SCHEMA]
FIX_TOOLS    = [READ_SCHEMA, SEARCH_SCHEMA, FUNC_SCHEMA, VERDICT_SCHEMA]
VERIFY_TOOLS = [READ_SCHEMA, SEARCH_SCHEMA, FUNC_SCHEMA, CALLER_SCHEMA, VERDICT_SCHEMA]
AUDIT_TOOLS  = [READ_SCHEMA, TRACE_SCHEMA, FUNC_SCHEMA, CALLER_SCHEMA, SEARCH_SCHEMA, VERDICT_SCHEMA]