READ_SCHEMA = {
    "type": "function",
    "function": {
        "name": "read_file",
        "description": "Read lines from a file in the workspace.",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Relative file path",
                },
                "start_line": {
                    "type": "integer",
                    "description": "First line to read (1-indexed, inclusive). Default: 1",
                },
                "end_line": {
                    "type": "integer",
                    "description": "Last line to read (1-indexed, inclusive). Default: 80",
                },
            },
            "required": ["path"],
        },
    },
}

TRACE_SCHEMA = {
    "type": "function",
    "function": {
        "name": "trace_variable",
        "description": "Perform AST-based alias analysis on a variable inside a file. Resolves the full alias chain: where the variable was defined, what it was assigned from, and every re-assignment up to the sink. MUST be called on every variable appearing in the sink call before concluding.",
        "parameters": {
            "type": "object",
            "properties": {
                "var_name": {
                    "type": "string",
                    "description": "The variable name to trace, e.g. 'user_id'",
                },
                "file_path": {
                    "type": "string",
                    "description": "Relative path of the file that contains the variable",
                },
            },
            "required": ["var_name", "file_path"],
        },
    },
}

FUNC_SCHEMA = {
    "type": "function",
    "function": {
        "name": "find_function",
        "description": "Search the entire codebase for the definition of a named function or method and return its full source code along with the file it lives in. Use this for cross-file analysis NEVER assume an unknown function is safe without calling this first.",
        "parameters": {
            "type": "object",
            "properties": {
                "function_name": {
                    "type": "string",
                    "description": "Name of the function or method to find, e.g. 'process_query'",
                },
            },
            "required": ["function_name"],
        },
    },
}

CALLER_SCHEMA = {
    "type": "function",
    "function": {
        "name": "find_callers",
        "description": "Find every location in the codebase that calls a given function, returning each caller's source code and file path. Useful for building a call graph or detecting how untrusted data propagates.",
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

SEARCH_SCHEMA = {
    "type": "function",
    "function": {
        "name": "search_pattern",
        "description": "Search the codebase for all occurrences of a text pattern (regex or literal). Use this to find sanitizers, validators, middleware, or specific API calls. Filter by file extension to limit scope.",
        "parameters": {
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "The regex or literal string pattern to search for, e.g. 'escape\\(|sanitize\\('",
                },
                "file_ext": {
                    "type": "string",
                    "description": "File extension filter, e.g. '.py', '.js', '.php'. Omit to search all files.",
                },
            },
            "required": ["pattern"],
        },
    },
}

VERDICT_SCHEMA = {
    "type": "function",
    "function": {
        "name": "submit_verdict",
        "description": "Submit the final verdict to terminate the analysis loop. This MUST be called with concrete evidence gathered from other tools. Do NOT call this without first tracing variables and checking for sanitizers.",
        "parameters": {
            "type": "object",
            "properties": {
                "verdict": {
                    "type": "string",
                    "enum": ["VULNERABLE", "SAFE"],
                    "description": "'VULNERABLE' only if an unbroken taint path to a dangerous sink is proven. 'SAFE' otherwise.",
                },
                "severity": {
                    "type": "string",
                    "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                    "description": "Severity based on CVSS impact.",
                },
                "confidence": {
                    "type": "integer",
                    "description": "Confidence score 0-100. Must be >= 70 to submit VULNERABLE.",
                },
                "cvss_estimate": {
                    "type": "number",
                    "description": "CVSS v3.1 base score estimate (0.0 - 10.0).",
                },
                "vuln_class": {
                    "type": "string",
                    "description": "CWE/vulnerability class, e.g. 'SQL Injection', 'Command Injection', 'IDOR'.",
                },
                "reasoning": {
                    "type": "string",
                    "description": "Chain-of-custody reasoning: source -> alias chain -> sink.",
                },
                "attack_vector": {
                    "type": "string",
                    "description": "(Optional) A concrete attack example.",
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
                    "description": "For PoC Verifier: True if the CVE can be exploited in the current context."
                },
                "extra_sinks": {
                    "type": "array",
                    "description": "For Sink Expander: List of new dangerous sink patterns discovered from the CVE context.",
                    "items": {
                        "type": "object",
                        "properties": {
                            "pattern": {"type": "string", "description": "Regex or literal pattern to search for."},
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

SCAN_TOOLS  = [READ_SCHEMA, TRACE_SCHEMA, FUNC_SCHEMA, CALLER_SCHEMA, VERDICT_SCHEMA]
AUDIT_TOOLS = [READ_SCHEMA, TRACE_SCHEMA, FUNC_SCHEMA, CALLER_SCHEMA, SEARCH_SCHEMA, VERDICT_SCHEMA]
HACK_TOOLS  = [READ_SCHEMA, SEARCH_SCHEMA, FUNC_SCHEMA, VERDICT_SCHEMA]
FIX_TOOLS   = [READ_SCHEMA, SEARCH_SCHEMA, FUNC_SCHEMA, VERDICT_SCHEMA]
VERIFY_TOOLS = [READ_SCHEMA, SEARCH_SCHEMA, FUNC_SCHEMA, VERDICT_SCHEMA]
EXPAND_TOOLS = [SEARCH_SCHEMA, VERDICT_SCHEMA]
