SANITIZERS = [
    # Python
    r"escape\(", r"sanitize\(", r"clean\(", r"validate\(", r"bleach\.clean", r"markupsafe", 
    r"html\.escape", r"parameterized", r"prepared", r"cursor\.execute.*%s",
    
    # JavaScript
    r"DOMPurify\.sanitize", r"encodeURIComponent", r"escapeHTML", r"validator\.escape", r"xss\(",
    
    # Java
    r"PreparedStatement", r"escapeXml", r"ESAPI\.encoder", r"HtmlUtils\.htmlEscape",
    
    # PHP
    r"htmlspecialchars", r"htmlentities", r"filter_var", r"mysqli_real_escape_string", r"pg_escape_string",
    
    # C/C++
    r"strlcpy", r"strlcat", r"snprintf",
    
    # Go
    r"html\.EscapeString", r"template\.HTMLEscapeString",
    
    # Chung
    r"allowlist", r"whitelist", r"permit",
]