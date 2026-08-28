import os
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List

from src.recognize.detector import EXCLUDES

DEPS = {
    # PHP
    "composer.json":      "packagist",
    "composer.lock":      "packagist",

    # JavaScript / TypeScript
    "package.json":       "npm",
    "package-lock.json":  "npm",
    "yarn.lock":          "npm",
    "pnpm-lock.yaml":     "npm",
    
    # Python
    "requirements.txt":   "pypi",
    "pyproject.toml":     "pypi",
    "poetry.lock":        "pypi",
    "Pipfile":            "pypi",
    "Pipfile.lock":       "pypi",
    "setup.cfg":          "pypi",
    "environment.yml":    "pypi",
    
    # Java / Kotlin / Android
    "pom.xml":            "maven",
    "build.gradle":       "maven",
    "build.gradle.kts":   "maven",
    
    # Go
    "go.mod":             "go",
    
    # Ruby
    "Gemfile":            "rubygems",
    "Gemfile.lock":       "rubygems",
    
    # C#
    "packages.config":    "nuget",
    
    # Rust
    "Cargo.toml":         "crates.io",
    "Cargo.lock":         "crates.io",
    
    # Dart / Flutter
    "pubspec.yaml":       "pub",
    "pubspec.lock":       "pub",
    
    # Elixir
    "mix.exs":            "hex",
    "mix.lock":           "hex",
    
    # C++ (vcpkg)
    "vcpkg.json":         "vcpkg",
    
    # C++ (Conan)
    "conanfile.txt":      "conan",
    "conanfile.py":       "conan",
    
    # Scala
    "build.sbt":          "maven",
}

# Parse PHP dependencies
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

# Parse NPM dependencies
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

# Parse NPM package-lock.json dependencies
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

# Parse Yarn yarn.lock dependencies
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

# Parse Python PyPI dependencies
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

# Parse Python pyproject.toml dependencies
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

# Parse Python poetry.lock dependencies
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

# Parse Java Maven dependencies
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

# Parse Go modules dependencies
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

# Parse RubyGems dependencies
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

# Parse C# .csproj dependencies
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

# Parse C# NuGet dependencies
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

# Parse Rust Cargo dependencies
def parse_cargo(path: str) -> List[Dict[str, str]]:
    deps = []
    
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()

        section = ""
        entry = {}

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith("[[") and line.endswith("]]"):
                if entry.get("package") and entry.get("version"):
                    deps.append({"ecosystem": "crates.io", **entry})
                entry = {}
                section = "package_list"
                continue
                
            if line.startswith("[") and line.endswith("]"):
                if entry.get("package") and entry.get("version"):
                    deps.append({"ecosystem": "crates.io", **entry})
                entry = {}
                section = line[1:-1]
                continue

            if "=" in line:
                parts = line.split("=", 1)
                key = parts[0].strip(' \'"')
                val = parts[1].strip()

                if section == "package_list":
                    if key == "name":
                        entry["package"] = val.strip(' \'"')
                    elif key == "version":
                        entry["version"] = val.strip(' \'"')
                    continue

                section_suffix = section.split(".")[-1].strip().strip("'\"")
                if section_suffix not in ("dependencies", "dev-dependencies", "build-dependencies"):
                    continue

                if val.startswith("{"):
                    ver = re.search(r'version\s*=\s*[\'"]([^\'"]+)[\'"]', val)
                else:
                    ver = re.match(r'^[\'"]([^\'"]+)[\'"]', val)

                if ver:
                    deps.append({"ecosystem": "crates.io", "package": key, "version": ver.group(1).strip('^~<>="')})

        if entry.get("package") and entry.get("version"):
            deps.append({"ecosystem": "crates.io", **entry})
            
    except Exception:
        pass
        
    return deps

# Parse Dart/Flutter pubspec dependencies
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

# Parse Elixir Mix dependencies
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

# Parse C++ vcpkg dependencies
def parse_vcpkg(path: str) -> List[Dict[str, str]]:
    deps = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            for item in data.get("dependencies", []):
                if isinstance(item, str):
                    deps.append({"ecosystem": "vcpkg", "package": item, "version": ""})
                elif isinstance(item, dict) and "name" in item:
                    ver = item.get("version>=", item.get("version", ""))
                    deps.append({"ecosystem": "vcpkg", "package": item["name"], "version": ver})
    except Exception:
        pass
    return deps

# Parse C++ conan dependencies
def parse_conan(path: str) -> List[Dict[str, str]]:
    deps = []
    
    try:
        with open(path, "r", encoding="utf-8") as f:
            in_requires = False
            for line in f:
                line = line.strip()
                if line.startswith("[requires]"):
                    in_requires = True
                    continue
                elif line.startswith("["):
                    in_requires = False
                
                if in_requires and line and not line.startswith("#"):
                    parts = line.split("/")
                    if len(parts) >= 2:
                        deps.append({"ecosystem": "conan", "package": parts[0].strip(), "version": parts[1].strip()})
    
    except Exception:
        pass
    
    return deps

# Parse Scala sbt dependencies
def parse_sbt(path: str) -> List[Dict[str, str]]:
    deps = []

    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
            # Parse "group" % "artifact" % "version" syntax
            pat = r'"([\w.\-]+)"\s*%{1,3}\s*"([\w.\-]+)"\s*%\s*"([\w.\-]+)"'

            for group, artifact, ver in re.findall(pat, content):
                deps.append({"ecosystem": "maven", "package": f"{group}:{artifact}", "version": ver})

    except Exception:
        pass

    return deps

# Parse strange dependencies
def parse_generic(path: str, ecosystem: str) -> List[Dict[str, str]]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except Exception:
        return []

    deps = []

    # --- JSON ---
    if path.endswith(".json"):
        try:
            data = json.loads(content)

            # Look for any dict value whose key contains "depend", "require", "package"
            for key, val in data.items():
                if any(k in key.lower() for k in ("depend", "require", "package", "lib")) and isinstance(val, dict):
                    for pkg, ver in val.items():
                        if isinstance(ver, str):
                            deps.append({"ecosystem": ecosystem, "package": pkg, "version": ver.strip("^~<>=")})
                        elif isinstance(ver, dict) and "version" in ver:
                            deps.append({"ecosystem": ecosystem, "package": pkg, "version": str(ver["version"]).strip("^~<>=")})
        except Exception:
            pass
        return deps

    # --- TOML ---
    if path.endswith((".toml",)):

        # Simple TOML: look for [*dependencies*] sections then key = "version" lines
        section = ""
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("["):
                section = line.strip("[]").strip()
            elif "depend" in section.lower() and "=" in line:
                pair = re.match(r'^([A-Za-z0-9_\-\.]+)\s*=\s*["\']?([^\'"{\s]+)', line)
                if pair:
                    deps.append({"ecosystem": ecosystem, "package": pair.group(1), "version": pair.group(2).strip("^~<>=")})
        return deps

    # --- YAML ---
    if path.endswith((".yaml", ".yml")):

        # Look for lines like "  - package==version" or "  package: version"
        for line in content.splitlines():
        
            # npm/pip style inline: "  package: version"
            m = re.match(r'^\s{1,6}([A-Za-z0-9_\-\.]+):\s+["\']?([0-9][^\s"\']+)', line)
            if m:
                deps.append({"ecosystem": ecosystem, "package": m.group(1), "version": m.group(2).strip("^~<>=")})
        return deps

    # --- Plain text ---
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # name==1.0 / name>=1.0 / name 1.0
        m = re.match(r'^([A-Za-z0-9_\-\.]+)\s*[=><~!]+\s*([0-9][^\s,;]*)', line) or \
            re.match(r'^([A-Za-z0-9_\-\.]+)\s+([0-9][^\s,;]*)', line)
        if m:
            deps.append({"ecosystem": ecosystem, "package": m.group(1), "version": m.group(2).strip("^~<>=")})

    return deps

# Parse Java/Kotlin/Android Gradle dependencies
def parse_gradle(path: str) -> List[Dict[str, str]]:
    deps = []
    
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
            
        # Matches: implementation 'group:artifact:version' or implementation("group:artifact:version")
        for m in re.finditer(r'''(?:implementation|api|compile|runtimeOnly|testImplementation|classpath)\s*[\('\"]([A-Za-z0-9_\-\.]+:[A-Za-z0-9_\-\.]+):([^\s'")\n]+)''', content):
            parts = m.group(1).split(":")
            pkg   = ":".join(parts)  # keep group:artifact as package name
            ver   = m.group(2).strip("'\")")
            deps.append({"ecosystem": "maven", "package": pkg, "version": ver.strip("^~<>=")})
    
    except Exception:
        pass
    
    return deps

# Parse Ruby Gemfile.lock
def parse_gemfile_lock(path: str) -> List[Dict[str, str]]:
    deps = []
    
    try:
        with open(path, "r", encoding="utf-8") as f:
            in_specs = False
            for line in f:
                stripped = line.rstrip()
                if stripped.strip() == "specs:":
                    in_specs = True
                    continue
                if in_specs:
                    
                    # Specs lines are indented: "    gem_name (version)"
                    m = re.match(r'^    ([A-Za-z0-9_\-\.]+)\s+\(([^\)]+)\)', stripped)
                    if m:
                        deps.append({"ecosystem": "rubygems", "package": m.group(1), "version": m.group(2).split(",")[0].strip()})
                    elif stripped and not stripped.startswith(" "):
                        in_specs = False
    
    except Exception:
        pass
    
    return deps

# Parse PHP composer.lock
def parse_composer_lock(path: str) -> List[Dict[str, str]]:
    deps = []
    
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for section in ("packages", "packages-dev"):
            for pkg in data.get(section, []):
                if "name" in pkg and "version" in pkg:
                    deps.append({"ecosystem": "packagist", "package": pkg["name"], "version": pkg["version"].lstrip("v")})
    
    except Exception:
        pass
    
    return deps

# Parse Python Pipfile 
def parse_pipfile(path: str) -> List[Dict[str, str]]:
    deps = []
    
    try:
        with open(path, "r", encoding="utf-8") as f:
            section = ""
            for line in f:
                line = line.strip()
                if line.startswith("["):
                    section = line.strip("[]").strip()
                elif section in ("packages", "dev-packages") and "=" in line:
                    m = re.match(r'^([A-Za-z0-9_\-\.]+)\s*=\s*["\']?([^"\'{\s]+)', line)
                    if m and m.group(2) != "*":
                        deps.append({"ecosystem": "pypi", "package": m.group(1), "version": m.group(2).strip("^~<>=")})
    
    except Exception:
        pass
    
    return deps

# Parse Python Pipfile.lock
def parse_pipfile_lock(path: str) -> List[Dict[str, str]]:
    deps = []
    
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for section in ("default", "develop"):
            for pkg, info in data.get(section, {}).items():
                ver = info.get("version", "").lstrip("=")
                if ver:
                    deps.append({"ecosystem": "pypi", "package": pkg, "version": ver})
    
    except Exception:
        pass
    
    return deps

# Parse Python setup.cfg
def parse_setup_cfg(path: str) -> List[Dict[str, str]]:
    deps = []
    
    try:
        with open(path, "r", encoding="utf-8") as f:
            in_requires = False
            for line in f:
                stripped = line.strip()
                if stripped in ("install_requires =", "install_requires="):
                    in_requires = True
                    continue
                if in_requires:
                    if not stripped or stripped.startswith("["):
                        in_requires = False
                        continue
                    m = re.match(r'^([A-Za-z0-9_\-\.]+)\s*([>=<!~^]+\s*[0-9][^\s,;]*)?', stripped)
                    if m:
                        ver = (m.group(2) or "").strip()
                        deps.append({"ecosystem": "pypi", "package": m.group(1), "version": re.sub(r'^[>=<!~^]+', '', ver).strip() or "unknown"})
    
    except Exception:
        pass
    
    return deps

# Parse JavaScript pnpm-lock.yaml
def parse_pnpm_lock(path: str) -> List[Dict[str, str]]:
    deps = []
    
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                
                # pnpm-lock format: /package-name@version: or /scope/package@version:
                m = re.match(r'^/(.+?)@([0-9][^:\s]+):', line)
                if m:
                    deps.append({"ecosystem": "npm", "package": m.group(1), "version": m.group(2).split("(")[0].strip()})
    
    except Exception:
        pass
    
    return deps

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

                elif name == "vcpkg.json":
                    manifests.extend(parse_vcpkg(full))

                elif name == "conanfile.txt":
                    manifests.extend(parse_conan(full))

                elif name == "build.sbt":
                    manifests.extend(parse_sbt(full))

                elif name in ["build.gradle", "build.gradle.kts"]:
                    manifests.extend(parse_gradle(full))

                elif name == "Gemfile.lock":
                    locks.extend(parse_gemfile_lock(full))

                elif name == "composer.lock":
                    locks.extend(parse_composer_lock(full))

                elif name == "Pipfile":
                    manifests.extend(parse_pipfile(full))

                elif name == "Pipfile.lock":
                    locks.extend(parse_pipfile_lock(full))

                elif name == "setup.cfg":
                    manifests.extend(parse_setup_cfg(full))

                elif name == "pnpm-lock.yaml":
                    locks.extend(parse_pnpm_lock(full))

                else:
                    manifests.extend(parse_generic(full, DEPS[name]))

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

# Report results
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