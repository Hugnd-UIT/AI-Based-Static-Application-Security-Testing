import json
import urllib.request
import urllib.parse
from typing import Dict, List

DEPS_DEV = "https://api.deps.dev/v3/systems/maven/packages/{}/versions/{}/dependencies"

def expand_maven(deps: List[Dict[str, str]]) -> List[Dict[str, str]]:
    out  = []
    seen = set()

    for dep in deps:
        if dep["ecosystem"] != "maven" or not dep.get("version"):
            continue

        pkg = urllib.parse.quote(dep["package"], safe="")
        ver = urllib.parse.quote(dep["version"], safe="")
        url = DEPS_DEV.format(pkg, ver)

        try:
            with urllib.request.urlopen(url, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except Exception:
            continue

        for node in data.get("nodes", [])[1:]:
            vkey     = node.get("versionKey", {})
            pkg_name = vkey.get("name", "")
            pkg_ver  = vkey.get("version", "")

            if not pkg_name or not pkg_ver:
                continue

            tag = (pkg_name.lower(), pkg_ver)
            if tag in seen:
                continue
            seen.add(tag)

            out.append({"ecosystem": "maven", "package": pkg_name, "version": pkg_ver})

    return out
