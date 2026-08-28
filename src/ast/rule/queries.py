QUERIES: dict[str, str] = {
    "python": """
        (function_definition name: (identifier) @name) @func
        (lambda) @func
    """,
    "javascript": """
        (function_declaration name: (identifier) @name) @func
        (function name: (identifier) @name) @func
        (arrow_function) @func
        (method_definition name: (property_identifier) @name) @func
    """,
    "typescript": """
        (function_declaration name: (identifier) @name) @func
        (function name: (identifier) @name) @func
        (arrow_function) @func
        (method_definition name: (property_identifier) @name) @func
    """,
    "java": """
        (method_declaration name: (identifier) @name) @func
        (constructor_declaration name: (identifier) @name) @func
        (lambda_expression) @func
    """,
    "ruby": """
        (method name: (identifier) @name) @func
        (singleton_method name: (identifier) @name) @func
        (lambda) @func
    """,
    "rust": """
        (function_item name: (identifier) @name) @func
        (closure_expression) @func
    """,
    "go": """
        (function_declaration name: (identifier) @name) @func
        (method_declaration name: (field_identifier) @name) @func
        (func_literal) @func
    """,
    "php": """
        (function_definition name: (name) @name) @func
        (method_declaration name: (name) @name) @func
        (arrow_function) @func
    """,
    "csharp": """
        (method_declaration name: (identifier) @name) @func
        (constructor_declaration name: (identifier) @name) @func
        (lambda_expression) @func
        (anonymous_method_expression) @func
    """,
    "scala": """
        (function_definition name: (identifier) @name) @func
    """,
    "cpp": """
        (function_definition declarator: (function_declarator declarator: (identifier) @name)) @func
    """,
    "c": """
        (function_definition declarator: (function_declarator declarator: (identifier) @name)) @func
    """,
}
