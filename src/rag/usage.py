import os
import re
from pathlib import Path
from typing import List, Dict, Any

SKIPS = {".git", "node_modules", "vendor", ".venv", "venv", "__pycache__", "target", "build", "dist", "bin", "obj", ".idea", ".vs"}

HEAD = re.compile(
    r"""^\s*(?:\#\s*include|\bimport\b|\bfrom\b|\brequire(?:_relative|_once)?\b|\binclude_once\b|\buse\b|\busing\b|\bextern\s+crate\b)""",
    re.IGNORECASE,
)

BARE = re.compile(r"""^\s*[\w.]*\s*['\"][^'\"]{3,}['\"]\s*,?\s*$""")

IMPORTS: Dict[str, str] = {}

def flat(txt: str) -> str:
    low = str(txt).lower()
    low = low.replace("::", "/")

    for ch in (".", "\\", ":", "-", "_", "@"):
        low = low.replace(ch, "/")

    while "//" in low:
        low = low.replace("//", "/")

    return low

def gen_alias(pkg: str) -> List[str]:
    raw = str(pkg).strip()

    if not raw:
        return []

    out = {flat(raw)}

    for part in re.split(r"[:/]", raw):
        part = part.strip()

        if len(part) > 2:
            out.add(flat(part))

    for one in list(out):
        for pre in ("py/", "python/", "go/", "node/", "rb/", "ruby/", "php/", "lib"):
            if one.startswith(pre) and len(one) - len(pre) > 2:
                out.add(one[len(pre):])

    return [a for a in out if len(a) > 2]

def gen_cache(target: str) -> str:
    if target in IMPORTS:
        return IMPORTS[target]

    lines = []

    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in SKIPS and not d.startswith(".")]

        for name in files:
            try:
                with open(os.path.join(root, name), "r", encoding="utf-8", errors="ignore") as fp:
                    body = fp.read()
            except Exception:
                continue

            for line in body.splitlines():
                if len(line) > 400:
                    continue

                if HEAD.search(line) or BARE.match(line):
                    lines.append(flat(line))

    IMPORTS[target] = "\n".join(lines)
    return IMPORTS[target]

# Check if imported
def check_imported(target: str, pkg: str) -> bool:
    if not pkg:
        return True

    text = gen_cache(target)

    if not text:
        return False

    return any(re.search(rf"\b{re.escape(alias)}\b", text) for alias in gen_alias(pkg))

# Check reachability
def check_usage(target: str, cves: List[Dict[str, Any]], ts) -> List[Dict[str, Any]]:
    if not cves or not os.path.exists(target):
        return cves

    for cve in cves:
        pkg_obj = cve.get("package", {})
        pkg = pkg_obj.get("name") if isinstance(pkg_obj, dict) else pkg_obj
        
        if pkg and not check_imported(target, pkg):
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
                                caller = ts.find_callers(tree.root_node, token, code_bytes, ext)
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