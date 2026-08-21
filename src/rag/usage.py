import os
import re
from pathlib import Path
from typing import List, Dict, Any

def is_package_imported(target_dir: str, pkg_name: str) -> bool:
    if not pkg_name: return True
    import_patterns = [
        re.compile(rf"""require\s*\(\s*['\"]{re.escape(pkg_name)}['\"\s]*\)"""),
        re.compile(rf"""from\s+['\"]{re.escape(pkg_name)}['\"]"""),
        re.compile(rf"""import\s+['\"]{re.escape(pkg_name)}['\"]"""),
        re.compile(rf"""import\s+\w+\s+from\s+['\"]{re.escape(pkg_name)}['\"]"""),
        re.compile(rf"""import\s+{re.escape(pkg_name)}"""),
        re.compile(rf"""use\s+.*{re.escape(pkg_name)}"""),
    ]
    skip_dirs = {".git", "node_modules", "vendor", ".venv", "__pycache__"}
    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for f in files:
            path = os.path.join(root, f)
            try:
                with open(path, 'r', encoding='utf-8') as fp:
                    content = fp.read()
                    for p in import_patterns:
                        if p.search(content):
                            return True
            except Exception:
                pass
    return False

def check_usage(target_dir: str, cve_list: List[Dict[str, Any]], ts_module) -> List[Dict[str, Any]]:
    if not cve_list or not os.path.exists(target_dir):

        return cve_list

    for cve_item in cve_list:
        pkg = cve_item.get("package", {})
        pkg_name = pkg.get("name") if isinstance(pkg, dict) else pkg
        if pkg_name and not is_package_imported(target_dir, pkg_name):
            cve_item["reachable"] = False
            continue
            
        cve_text = cve_item.get("summary", "") + "\n" + cve_item.get("details", "")
        cve_tokens = set()
        
        for text_token in re.findall(r'`([^`]+)`', cve_text):
            text_token = text_token.strip()

            if '(' in text_token: text_token = text_token.split('(')[0]

            if '.' in text_token: text_token = text_token.split('.')[-1]

            if re.match(r'^[a-zA-Z_]\w*$', text_token) and len(text_token) > 2:
                cve_tokens.add(text_token)

        if not cve_tokens:
            cve_item["reachable"] = True
            continue

        is_reachable = False

        for text_token in cve_tokens:

            for file_ext, lang_obj in ts_module.LANG.items():

                try:
                    ts_parser = ts_module.Parser(ts_module.Language(lang_obj))

                except Exception:

                    try:
                        ts_parser = ts_module.Parser()
                        ts_parser.set_language(ts_module.Language(lang_obj))

                    except Exception:
                        continue

                # Walk directory and parse files for this extension
                for root, dirs, files in os.walk(target_dir):
                    if "node_modules" in dirs: dirs.remove("node_modules")
                    if ".git" in dirs: dirs.remove(".git")
                    if "vendor" in dirs: dirs.remove("vendor")
                    
                    for f in files:
                        if f.endswith(file_ext):
                            f_path = os.path.join(root, f)
                            try:
                                with open(f_path, 'r', encoding='utf-8') as fp:
                                    code_str = fp.read()
                                code_bytes = code_str.encode("utf-8")
                                tree = ts_parser.parse(code_bytes)
                                caller_ctx = ts_module.find_callers(tree.root_node, text_token, code_bytes)
                                if caller_ctx:
                                    is_reachable = True
                                    break
                            except Exception:
                                pass
                    if is_reachable:
                        break

            if is_reachable:
                break

        cve_item["reachable"] = is_reachable

    return cve_list

