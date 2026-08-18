import os
import re
from pathlib import Path
from typing import List, Dict, Any

def check(target_dir: str, cve_list: List[Dict[str, Any]], ts_module) -> List[Dict[str, Any]]:
    if not cve_list or not os.path.exists(target_dir):
        return cve_list

    for cve in cve_list:
        text = cve.get("summary", "") + "\n" + cve.get("details", "")
        tokens = set()
        
        for t in re.findall(r'`([^`]+)`', text):
            t = t.strip()
            if '(' in t: t = t.split('(')[0]
            if '.' in t: t = t.split('.')[-1]
            if re.match(r'^[a-zA-Z_]\w*$', t) and len(t) > 2:
                tokens.add(t)

        if not tokens:
            cve["reachable"] = True
            continue

        reachable = False
        for t in tokens:
            for ext, lang in ts_module.LANG.items():
                ts_parser = ts_module.Parser(ts_module.Language(lang))
                caller_ctx = ts_module.find_global_callers(target_dir, t, ext, ts_parser)
                if caller_ctx:
                    reachable = True
                    break
            if reachable:
                break

        cve["reachable"] = reachable

    return cve_list
