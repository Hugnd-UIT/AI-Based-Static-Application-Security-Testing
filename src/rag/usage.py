import os
import re
from pathlib import Path
from typing import List, Dict, Any

def check_usage(target_dir: str, cve_list: List[Dict[str, Any]], ts_module) -> List[Dict[str, Any]]:
    if not cve_list or not os.path.exists(target_dir):

        return cve_list

    for cve_item in cve_list:
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

                caller_ctx = ts_module.find_callers(target_dir, text_token, file_ext, ts_parser)

                if caller_ctx:
                    is_reachable = True
                    break

            if is_reachable:
                break

        cve_item["reachable"] = is_reachable

    return cve_list

