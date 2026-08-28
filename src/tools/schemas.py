# File reading tool
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

# Variable tracing tool
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

# Function finding tool
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

# Caller finding tool
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

# Pattern search tool
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

# Shared data fields
SHARE_PROPS = {
    "verdict": {
        "type": "string",
        "enum": ["VULNERABLE", "SAFE"],
        "description": "'VULNERABLE' if an unbroken taint path to a dangerous sink is proven, 'SAFE' otherwise",
    },
    "confidence": {
        "type": "integer",
        "description": "Confidence score 0-100 - Must be >= 70 to submit VULNERABLE",
    },
    "reason": {
        "type": "string",
        "description": "Chain-of-custody reasoning: source -> alias chain -> sink",
    },
}

# Scan agent specific data fields
SCAN_PROPS = {
    "flow": {
        "type": "array",
        "description": "One entry per hop, in chronological order from source to sink",
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
    "broken_flow": {"type": "boolean"},
    "surrogate": {
        "type": "boolean",
        "description": "True when the flow is broken and you are proposing a surrogate sink instead",
    },
    "surrogate_function": {
        "type": "string",
        "description": "Upstream caller to treat as the new sink when 'surrogate' is true",
    },
}

# Audit agent specific data fields
AUDIT_PROPS = {
    "severity": {
        "type": "string",
        "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        "description": "Severity based on CVSS impact",
    },
    "cvss": {
        "type": "number",
        "description": "CVSS v3.1 base score estimate (0.0 - 10.0)",
    },
    "attack_vector": {
        "type": "string",
        "description": "(Optional) A concrete attack example",
    },
    "source_variable": {"type": "string"},
    "sink_function": {"type": "string"},
    "flow": SCAN_PROPS["flow"],
    "fp_source": {
        "type": "boolean",
        "description": "True if the reported source is NOT attacker controlled (hardcoded value, config file, trusted internal caller). Setting this forces the finding to SAFE.",
    },
    "fp_sink": {
        "type": "boolean",
        "description": "True if the reported sink is NOT actually dangerous with this argument (parameterized query, logging only, escaped by the framework). Setting this forces the finding to SAFE.",
    },
}

# Fix agent specific data fields
FIX_PROPS = {
    "explanation": {
        "type": "string",
        "description": "Why this fix works and what it prevents",
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
}

# Verify agent specific data fields
VERIFY_PROPS = {
    "exploitable": {
        "type": "boolean",
        "description": "True if the CVE can be exploited in the current context",
    },
    "poc": {"type": "string"},
    "payload": {"type": "string"},
    "description": {"type": "string"},
}

# Expand agent specific data fields
EXPAND_PROPS = {
    "extra_sinks": {
        "type": "array",
        "description": "New dangerous sink patterns discovered from the CVE context",
        "items": {
            "type": "object",
            "properties": {
                "pattern": {"type": "string", "description": "Regex or literal pattern to search for"},
                "severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]},
                "description": {"type": "string"},
            },
        },
    },
}

# Verdict function
def verdict(props: dict, desc: str) -> dict:
    return {
        "type": "function",
        "function": {
            "name": "submit_verdict",
            "description": desc,
            "parameters": {
                "type": "object",
                "properties": {**SHARE_PROPS, **props},
                "required": ["verdict", "confidence", "reason"],
            },
        },
    }

SCAN_VERDICT   = verdict(
    SCAN_PROPS,
    "Submit the traced data flow to terminate the analysis loop - Fill 'flow' with every hop you proved, or set 'surrogate' if the flow is broken",
)

AUDIT_VERDICT  = verdict(
    AUDIT_PROPS,
    "Submit the final verdict to terminate the analysis loop - MUST be called with concrete evidence gathered from other tools",
)

FIX_VERDICT    = verdict(
    FIX_PROPS,
    "Submit the patches to terminate the analysis loop - 'old_code' must match the file character-for-character",
)

VERIFY_VERDICT = verdict(
    VERIFY_PROPS,
    "Submit the exploitability decision to terminate the analysis loop - Say exactly what you searched for in 'reason'",
)

EXPAND_VERDICT = verdict(
    EXPAND_PROPS,
    "Submit the new sink patterns to terminate the analysis loop - Only include patterns you verified with search_pattern",
)

SCAN_TOOLS = [
    READ_SCHEMA,
    TRACE_SCHEMA,
    FUNC_SCHEMA,
    CALLER_SCHEMA,
    SCAN_VERDICT,
]

AUDIT_TOOLS = [
    READ_SCHEMA,
    TRACE_SCHEMA,
    FUNC_SCHEMA,
    CALLER_SCHEMA,
    SEARCH_SCHEMA,
    AUDIT_VERDICT,
]

FIX_TOOLS = [
    READ_SCHEMA,
    SEARCH_SCHEMA,
    FUNC_SCHEMA,
    FIX_VERDICT,
]

VERIFY_TOOLS = [
    READ_SCHEMA,
    SEARCH_SCHEMA,
    FUNC_SCHEMA,
    CALLER_SCHEMA,
    VERIFY_VERDICT,
]

EXPAND_TOOLS = [
    SEARCH_SCHEMA,
    EXPAND_VERDICT,
]

