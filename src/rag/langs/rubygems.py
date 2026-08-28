import json
import urllib.request
from typing import Dict, List

GEMS = "https://rubygems.org/api/v2/rubygems/{}/versions/{}.json"

def expand_gems(deps: List[Dict[str, str]]) -> List[Dict[str, str]]:
    out = []

    for dep in deps:
        if dep["ecosystem"] != "rubygems" or not dep.get("version"):
            continue

        try:
            url = GEMS.format(dep["package"], dep["version"])
            with urllib.request.urlopen(url, timeout=15) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except Exception:
            continue

        for sub in data.get("dependencies", {}).get("runtime", []):
            req = str(sub.get("requirements", "")).strip()

            if not req.startswith("="):
                continue

            out.append({
                "ecosystem": "rubygems",
                "package":   sub.get("name", ""),
                "version":   req.lstrip("= ").strip(),
            })

    return [d for d in out if d["package"] and d["version"]]
