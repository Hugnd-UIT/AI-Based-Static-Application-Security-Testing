import os
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List

from src.recognize.detector import EXCLUDES

DEPS = {
    "composer.json": "packagist",
    "package.json": "npm",
    "package-lock.json": "npm",
    "yarn.lock": "npm",
    "requirements.txt": "pypi",
    "pyproject.toml": "pypi",
    "poetry.lock": "pypi",
    "pom.xml": "maven",
    "go.mod": "go",
    "Gemfile": "rubygems",
    "packages.config": "nuget",
    "Cargo.toml": "crates.io",
    "Cargo.lock": "crates.io",
    "pubspec.yaml": "pub",
    "pubspec.lock": "pub",
    "mix.exs": "hex",
    "mix.lock": "hex",
}

# Hàm phân tích thư viện php
def parse_php(path: str) -> List[Dict[str, str]]:
    deps = []

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            reqs = {**data.get("require", {}), **data.get("require-dev", {})}

            for pkg, ver in reqs.items():

                if pkg == "php" or "/" not in pkg:
                    continue

                deps.append(
                    {
                        "ecosystem": "packagist",
                        "package": pkg,
                        "version": ver.strip("^~<>="),
                    }
                )

    except Exception:
        pass

    return deps

# Hàm phân tích thư viện npm
def parse_npm(path: str) -> List[Dict[str, str]]:
    deps = []

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            reqs = {**data.get("dependencies", {}), **data.get("devDependencies", {})}

            for pkg, ver in reqs.items():
                deps.append(
                    {"ecosystem": "npm", "package": pkg, "version": ver.strip("^~<>=")}
                )

    except Exception:
        pass

    return deps

# Hàm phân tích thư viện package lock
def parse_package_lock(path: str) -> List[Dict[str, str]]:
    deps = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if "packages" in data:
                for p, info in data["packages"].items():
                    if p and "node_modules/" in p:
                        pkg = p.split("node_modules/")[-1]
                        if "version" in info:
                            deps.append({"ecosystem": "npm", "package": pkg, "version": info["version"]})
            elif "dependencies" in data:
                for pkg, info in data["dependencies"].items():
                    if "version" in info:
                        deps.append({"ecosystem": "npm", "package": pkg, "version": info["version"]})
    except Exception:
        pass
    return deps

# Hàm phân tích thư viện yarn lock
def parse_yarn_lock(path: str) -> List[Dict[str, str]]:
    deps = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
            matches = re.findall(r'^"?(@?[a-zA-Z0-9_\-\.]+)(?:@[^"]+)?(?:,.*?)?:\n\s*version\s+"([^"]+)"', content, re.MULTILINE)
            for pkg, ver in matches:
                deps.append({"ecosystem": "npm", "package": pkg, "version": ver})
    except Exception:
        pass
    return deps

# Hàm phân tích thư viện pypi
def parse_pypi(path: str) -> List[Dict[str, str]]:
    deps = []

    try:
        with open(path, "r", encoding="utf-8") as f:

            for line in f:
                line = line.strip()

                if not line or line.startswith("#") or line.startswith("-"):
                    continue

                line = line.split(";")[0].strip()
                match = re.search(r'([><=!~]+)\s*([\w.]+)', line)

                if match:
                    pkg = line[:match.start()].strip()
                    ver = match.group(2).strip()
                    pkg = re.sub(r'\[.*?\]', '', pkg).strip()

                    if pkg:
                        deps.append(
                            {
                                "ecosystem": "pypi",
                                "package": pkg,
                                "version": ver,
                            }
                        )

                else:
                    pkg = re.sub(r'\[.*?\]', '', line).strip()

                    if pkg:
                        deps.append(
                            {
                                "ecosystem": "pypi",
                                "package": pkg,
                                "version": "",
                            }
                        )

    except Exception:
        pass

    return deps

# Hàm phân tích thư viện pyproject
def parse_pyproject(path: str) -> List[Dict[str, str]]:
    deps = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
            matches = re.findall(r'^([a-zA-Z0-9_\-]+)\s*=\s*[\'"]([^\'"]+)[\'"]', content, re.MULTILINE)
            for pkg, ver in matches:
                deps.append({"ecosystem": "pypi", "package": pkg, "version": ver.strip('^~<>="')})
    except Exception:
        pass
    return deps

# Hàm phân tích thư viện poetry lock
def parse_poetry_lock(path: str) -> List[Dict[str, str]]:
    deps = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            blocks = f.read().split("[[package]]")
            for block in blocks[1:]:
                n_match = re.search(r'name\s*=\s*"([^"]+)"', block)
                v_match = re.search(r'version\s*=\s*"([^"]+)"', block)
                if n_match and v_match:
                    deps.append({"ecosystem": "pypi", "package": n_match.group(1), "version": v_match.group(1)})
    except Exception:
        pass
    return deps

# Hàm phân tích thư viện maven
def parse_maven(path: str) -> List[Dict[str, str]]:
    deps = []

    try:
        tree = ET.parse(path)
        root = tree.getroot()
        ns = ""

        if root.tag.startswith("{"):
            ns = root.tag.split("}")[0] + "}"

        for node in root.findall(f".//{ns}dependency"):
            group = node.find(f"{ns}groupId")
            artifact = node.find(f"{ns}artifactId")
            ver = node.find(f"{ns}version")

            if group is not None and artifact is not None and ver is not None:

                if "$" not in ver.text:
                    pkg = f"{group.text}:{artifact.text}"
                    deps.append(
                        {"ecosystem": "maven", "package": pkg, "version": ver.text}
                    )

    except Exception:
        pass

    return deps

# Hàm phân tích thư viện go
def parse_go(path: str) -> List[Dict[str, str]]:
    deps = []

    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
            matches = re.findall(r"([a-zA-Z0-9.\-_/]+)\s+v([0-9a-zA-Z.\-_]+)", content)

            for pkg, ver in matches:

                if pkg != "go":
                    deps.append({"ecosystem": "go", "package": pkg, "version": ver})

    except Exception:
        pass

    return deps

# Hàm phân tích thư viện ruby
def parse_ruby(path: str) -> List[Dict[str, str]]:
    deps = []

    try:
        with open(path, "r", encoding="utf-8") as f:

            for line in f:
                line = line.strip()

                if line.startswith("gem "):
                    match = re.search(
                        r"""gem\s+['"]([^'"]+)['"](?:\s*,\s*['"]([^'"]+)['"])?""", line
                    )

                    if match:
                        pkg = match.group(1)
                        ver = match.group(2) if match.group(2) else ""
                        ver = re.sub(r"^[~>=<\s]+", "", ver)

                        deps.append(
                            {"ecosystem": "rubygems", "package": pkg, "version": ver}
                        )

    except Exception:
        pass

    return deps

# Hàm phân tích thư viện csproj
def parse_csproj(path: str) -> List[Dict[str, str]]:
    deps = []

    try:
        tree = ET.parse(path)
        root = tree.getroot()

        for node in root.findall(".//PackageReference"):
            pkg = node.get("Include")
            ver = node.get("Version")

            if pkg and ver:
                deps.append({"ecosystem": "nuget", "package": pkg, "version": ver})

    except Exception:
        pass

    return deps

# Hàm phân tích thư viện nuget
def parse_nuget(path: str) -> List[Dict[str, str]]:
    deps = []

    try:
        tree = ET.parse(path)
        root = tree.getroot()

        for node in root.findall(".//package"):
            pkg = node.get("id")
            ver = node.get("version")

            if pkg and ver:
                deps.append({"ecosystem": "nuget", "package": pkg, "version": ver})

    except Exception:
        pass

    return deps

# Hàm phân tích thư viện cargo
def parse_cargo(path: str) -> List[Dict[str, str]]:
    deps = []
    
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
            matches = re.findall(r'^([a-zA-Z0-9_\-]+)\s*=\s*(?:\{.*?version\s*=\s*)?[\'"]([^\'"]+)[\'"]', content, re.MULTILINE)
            
            for pkg, ver in matches:
                deps.append({"ecosystem": "crates.io", "package": pkg, "version": ver.strip('^~<>="')})
    
    except Exception:
        pass
    
    return deps

# Hàm phân tích thư viện pubspec
def parse_pubspec(path: str) -> List[Dict[str, str]]:
    deps = []
    
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
            matches = re.findall(r'^\s*([a-zA-Z0-9_]+):\s*[\'"]?([><=^~]*\s*\d+\.\d+\.\d+.*?)[\'"]?$', content, re.MULTILINE)
    
            for pkg, ver in matches:
                deps.append({"ecosystem": "pub", "package": pkg, "version": ver.strip('^~<>=" ')})
    except Exception:
        pass
    
    return deps

# Hàm phân tích thư viện mix
def parse_mix(path: str) -> List[Dict[str, str]]:
    deps = []
    
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
            matches = re.findall(r'\{:\s*([a-zA-Z0-9_]+)\s*,\s*[\'"]([^"\'\n]+)[\'"]', content)
    
            for pkg, ver in matches:
                deps.append({"ecosystem": "hex", "package": pkg, "version": ver.strip('^~<>=" ')})
    
    except Exception:
        pass
    
    return deps

# Hàm phân tích thư viện
def parse_deps(target: str) -> List[Dict[str, str]]:
    path = Path(target)

    if not path.exists() or not path.is_dir():
        raise ValueError(f"[!] The path is invalid: {target}")

    manifests = []
    locks = []

    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in EXCLUDES]

        for name in files:
            full = os.path.join(root, name)

            if name in DEPS:

                if name == "composer.json":
                    manifests.extend(parse_php(full))

                elif name == "package.json":
                    manifests.extend(parse_npm(full))
                    
                elif name == "package-lock.json":
                    locks.extend(parse_package_lock(full))
                    
                elif name == "yarn.lock":
                    locks.extend(parse_yarn_lock(full))

                elif name == "requirements.txt":
                    manifests.extend(parse_pypi(full))
                    
                elif name == "pyproject.toml":
                    manifests.extend(parse_pyproject(full))
                    
                elif name == "poetry.lock":
                    locks.extend(parse_poetry_lock(full))

                elif name == "pom.xml":
                    manifests.extend(parse_maven(full))

                elif name == "go.mod":
                    manifests.extend(parse_go(full))

                elif name == "Gemfile":
                    manifests.extend(parse_ruby(full))

                elif name == "packages.config":
                    manifests.extend(parse_nuget(full))

                elif name in ["Cargo.toml", "Cargo.lock"]:
                    manifests.extend(parse_cargo(full))

                elif name in ["pubspec.yaml", "pubspec.lock"]:
                    manifests.extend(parse_pubspec(full))

                elif name in ["mix.exs", "mix.lock"]:
                    manifests.extend(parse_mix(full))

            elif name.endswith(".csproj"):
                manifests.extend(parse_csproj(full))

    mapping = {(d["ecosystem"], d["package"]): d["version"] for d in locks}
    
    finals = []
    seen = set()
    
    for d in manifests + locks:
        key = (d["ecosystem"], d["package"])
        if key in seen:
            continue
        seen.add(key)
        
        if key in mapping:
            d["version"] = mapping[key]
        finals.append(d)

    return finals

from cli.views import logger

# Hàm báo cáo kết quả
def report_deps(deps: List[Dict[str, str]]):
    logger.section("DEPENDENCIES")

    if not deps:
        logger.warning("No dependencies found!")
        return

    from cli.views.logger import console
    console.print(f"  [cyan]{len(deps)}[/cyan] dependencies detected")
    console.print()

    for dep in deps:
        console.print(f"  - [magenta]{dep['ecosystem']}[/magenta] [blue]{dep['package']}[/blue] v{dep['version']}")