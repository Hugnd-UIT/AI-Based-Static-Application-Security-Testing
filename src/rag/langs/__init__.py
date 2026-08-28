from typing import Dict, List

from src.rag.langs.rubygems import expand_gems
from src.rag.langs.maven import expand_maven


# Expand deps before OSV
def expand_before_osv(deps: List[Dict[str, str]]) -> List[Dict[str, str]]:
    extra = []

    maven_deps = [d for d in deps if d["ecosystem"] == "maven" and d.get("version")]
    if maven_deps:
        extra.extend(expand_maven(maven_deps))

    return extra


# Expand deps after OSV
def expand_after_osv(zero_deps: List[Dict[str, str]]) -> List[Dict[str, str]]:
    ruby_deps = [d for d in zero_deps if d["ecosystem"] == "rubygems"]
    if ruby_deps:
        return expand_gems(ruby_deps)

    return []
