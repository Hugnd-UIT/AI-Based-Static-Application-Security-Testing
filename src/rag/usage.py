import os
import re
from pathlib import Path
from typing import List, Dict, Any

# Hàm kiểm tra package được sử dụng hay không
def is_imported(target: str, pkg: str) -> bool:
    if not pkg: return True
    patterns = [
        re.compile(rf"""require\s*\(\s*['\"]{re.escape(pkg)}['\"\s]*\)"""),
        re.compile(rf"""from\s+['\"]{re.escape(pkg)}['\"]"""),
        re.compile(rf"""import\s+['\"]{re.escape(pkg)}['\"]"""),
        re.compile(rf"""import\s+\w+\s+from\s+['\"]{re.escape(pkg)}['\"]"""),
        re.compile(rf"""import\s+{re.escape(pkg)}"""),
        re.compile(rf"""use\s+.*{re.escape(pkg)}"""),
        re.compile(rf"""extern\s+crate\s+{re.escape(pkg)}"""),
        re.compile(rf"""import\s+['\"]package:{re.escape(pkg)}.*['\"]"""),
        re.compile(rf"""alias\s+.*{re.escape(pkg)}"""),
        re.compile(rf"""#include\s*[<\"](.*{re.escape(pkg)}.*)[>\"]""", re.IGNORECASE),
    ]
    skips = {".git", "node_modules", "vendor", ".venv", "__pycache__"}
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in skips]
        for f in files:
            path = os.path.join(root, f)
            try:
                with open(path, 'r', encoding='utf-8') as fp:
                    content = fp.read()
                    for p in patterns:
                        if p.search(content):
                            return True
            except Exception:
                pass
    return False

# Hàm kiểm tra khả năng dính lỗ hổng
def check_usage(target: str, cves: List[Dict[str, Any]], ts) -> List[Dict[str, Any]]:
    if not cves or not os.path.exists(target):
        return cves

    for cve in cves:
        pkg_obj = cve.get("package", {})
        pkg = pkg_obj.get("name") if isinstance(pkg_obj, dict) else pkg_obj
        if pkg and not is_imported(target, pkg):
            cve["reachable"] = False
            continue
            
        text = cve.get("summary", "") + "\n" + cve.get("details", "")
        tokens = set()
        
        for token in re.findall(r'`([^`]+)`', text):
            token = token.strip()

            if '(' in token: token = token.split('(')[0]
            if '.' in token: token = token.split('.')[-1]

            if re.match(r'^[a-zA-Z_]\w*$', token) and len(token) > 2:
                tokens.add(token)

        COMMON = {
            "exec", "open", "read", "write", "close", "get", "set", "add",
            "run", "start", "stop", "init", "load", "save", "delete", "parse",
            "send", "recv", "connect", "create", "update", "find", "check",
            "call", "apply", "use", "new", "from", "to", "of", "with",
        }
        tokens = {t for t in tokens if len(t) > 4 and t not in COMMON}

        if not tokens:
            cve["reachable"] = True
            continue

        reachable = False

        for token in tokens:
            for ext, lang in ts.LANG.items():
                try:
                    parser = ts.Parser(ts.Language(lang))
                except Exception:
                    try:
                        parser = ts.Parser()
                        parser.set_language(ts.Language(lang))
                    except Exception:
                        continue

                for root, dirs, files in os.walk(target):
                    if "node_modules" in dirs: dirs.remove("node_modules")
                    if ".git" in dirs: dirs.remove(".git")
                    if "vendor" in dirs: dirs.remove("vendor")
                    
                    for f in files:
                        if f.endswith(ext):
                            path = os.path.join(root, f)
                            try:
                                with open(path, 'r', encoding='utf-8') as fp:
                                    code = fp.read()
                                code_bytes = code.encode("utf-8")
                                tree = parser.parse(code_bytes)
                                caller = ts.find_callers(tree.root_node, token, code_bytes)
                                if caller:
                                    reachable = True
                                    break
                            except Exception:
                                pass
                    if reachable:
                        break
            if reachable:
                break

        cve["reachable"] = reachable

    return cves
