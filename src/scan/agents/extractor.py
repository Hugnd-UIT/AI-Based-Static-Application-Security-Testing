import os
import re
import json

def extract_functions(target_dir):
    extensions = {
        ".js": "javascript",
        ".py": "python",
        ".java": "java",
        ".rb": "ruby",
        ".rs": "rust",
        ".scala": "scala",
        ".php": "php",
        ".ts": "typescript",
        ".cs": "csharp",
        ".go": "go",
        ".cpp": "cpp",
        ".c": "c"
    }

    patterns = {
        "python": re.compile(r'^\s*(?:async\s+)?def\s+([a-zA-Z_]\w*)\s*\([^)]*\):', re.MULTILINE),
        "javascript": re.compile(r'(?:function\s+([a-zA-Z_]\w*)\s*\(|([a-zA-Z_]\w*)\s*[:=]\s*(?:async\s+)?(?:function\s*)?\(|([a-zA-Z_]\w*)\s*[:=]\s*(?:async\s+)?(?:\w+|\([^)]*\))\s*=>)', re.MULTILINE),
        "typescript": re.compile(r'(?:function\s+([a-zA-Z_]\w*)\s*\(|([a-zA-Z_]\w*)\s*[:=]\s*(?:async\s+)?(?:function\s*)?\(|([a-zA-Z_]\w*)\s*[:=]\s*(?:async\s+)?(?:\w+|\([^)]*\))\s*=>)', re.MULTILINE),
        "java": re.compile(r'(?:public|protected|private|static|\s)+[\w\<\>\[\]]+\s+([a-zA-Z_]\w*)\s*\([^\)]*\)\s*(?:throws\s+[\w\s,]+)?\s*\{', re.MULTILINE),
        "ruby": re.compile(r'^\s*def\s+([a-zA-Z_]\w*[=!?]?)', re.MULTILINE),
        "rust": re.compile(r'^\s*(?:pub\s+)?(?:async\s+)?fn\s+([a-zA-Z_]\w*)\s*\(', re.MULTILINE),
        "scala": re.compile(r'^\s*(?:private|protected|override|\s)*def\s+([a-zA-Z_]\w*)\s*\(', re.MULTILINE),
        "php": re.compile(r'(?:public|protected|private|static|\s)*function\s+([a-zA-Z_]\w*)\s*\(', re.MULTILINE),
        "csharp": re.compile(r'(?:public|protected|private|internal|static|\s)+[\w\<\>\[\]]+\s+([a-zA-Z_]\w*)\s*\([^\)]*\)\s*\{', re.MULTILINE),
        "go": re.compile(r'^\s*func\s+(?:\[[^\]]+\]\s+)?(?:\([^)]+\)\s+)?([a-zA-Z_]\w*)\s*\(', re.MULTILINE),
        "cpp": re.compile(r'^\s*(?:virtual|static|inline|\s)*[\w\<\>\[\]\*\&]+\s+([a-zA-Z_]\w*)\s*\([^\)]*\)\s*(?:const)?\s*(?:override)?\s*\{', re.MULTILINE),
        "c": re.compile(r'^\s*(?:static|inline|\s)*[\w\<\>\[\]\*\&]+\s+([a-zA-Z_]\w*)\s*\([^\)]*\)\s*\{', re.MULTILINE)
    }

    results = []

    for root, _, files in os.walk(target_dir):
        # Bỏ qua các thư mục không cần thiết
        if any(ignored in root for ignored in ['node_modules', 'vendor', 'target', 'build', 'dist', '.git', '__pycache__', 'venv', '.venv']):
            continue

        for file in files:
            ext = os.path.splitext(file)[1]
            if ext in extensions:
                lang = extensions[ext]
                fpath = os.path.join(root, file)
                
                try:
                    with open(fpath, "r", encoding="utf-8") as f:
                        content = f.read()
                        
                    if lang not in patterns:
                        continue
                        
                    matches = patterns[lang].finditer(content)
                    for match in matches:
                        func_name = next((g for g in match.groups() if g), "anonymous")
                        
                        start_idx = match.start()
                        end_idx = content.find("\n", start_idx)
                        if end_idx == -1: end_idx = len(content)
                        
                        signature = content[start_idx:end_idx].strip()
                        if signature.endswith("{"):
                            signature = signature[:-1].strip()
                            
                        docstring = ""
                        lines_before = content[:start_idx].split("\n")
                        if lines_before:
                            prev_line = lines_before[-2].strip() if len(lines_before) > 1 else ""
                            if prev_line.endswith("*/") or prev_line.endswith('"""') or prev_line.startswith("#") or prev_line.startswith("//"):
                                docstring = prev_line
                                
                        rel_path = os.path.relpath(fpath, target_dir)
                                
                        results.append({
                            "file": rel_path.replace("\\", "/"),
                            "function": func_name,
                            "signature": signature,
                            "context": docstring,
                            "language": lang
                        })
                except Exception as e:
                    pass

    return results