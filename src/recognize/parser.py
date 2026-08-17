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
    "requirements.txt": "pypi",
    "pom.xml": "maven",
    "go.mod": "go",
    "Gemfile": "rubygems",
    "packages.config": "nuget",
}

def parse_php(file_path: str) -> List[Dict[str, str]]:
    parsed_deps = []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            json_data = json.load(f)
            req_dict = {**json_data.get("require", {}), **json_data.get("require-dev", {})}

            for pkg_name, pkg_version in req_dict.items():
                if pkg_name == "php" or "/" not in pkg_name:
                    continue

                parsed_deps.append(
                    {
                        "ecosystem": "packagist",
                        "package": pkg_name,
                        "version": pkg_version.strip("^~<>="),
                    }
                )
    except Exception:
        pass
    return parsed_deps

def parse_npm(file_path: str) -> List[Dict[str, str]]:
    parsed_deps = []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            json_data = json.load(f)
            req_dict = {**json_data.get("dependencies", {}), **json_data.get("devDependencies", {})}

            for pkg_name, pkg_version in req_dict.items():
                parsed_deps.append(
                    {"ecosystem": "npm", "package": pkg_name, "version": pkg_version.strip("^~<>=")}
                )
    except Exception:
        pass
    return parsed_deps

def parse_pypi(file_path: str) -> List[Dict[str, str]]:
    parsed_deps = []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()

                if not line or line.startswith("#"):
                    continue

                if "==" in line:
                    pkg_name, pkg_version = line.split("==", 1)
                    parsed_deps.append(
                        {
                            "ecosystem": "pypi",
                            "package": pkg_name.strip(),
                            "version": pkg_version.strip(),
                        }
                    )
    except Exception:
        pass
    return parsed_deps

def parse_maven(file_path: str) -> List[Dict[str, str]]:
    parsed_deps = []
    try:
        xml_tree = ET.parse(file_path)
        xml_root = xml_tree.getroot()
        namespace = ""

        if xml_root.tag.startswith("{"):
            namespace = xml_root.tag.split("}")[0] + "}"

        for dep_node in xml_root.findall(f".//{namespace}dependency"):
            group_id = dep_node.find(f"{namespace}groupId")
            artifact_id = dep_node.find(f"{namespace}artifactId")
            pkg_version = dep_node.find(f"{namespace}version")

            if group_id is not None and artifact_id is not None and pkg_version is not None:
                if "$" not in pkg_version.text:
                    pkg_name = f"{group_id.text}:{artifact_id.text}"
                    parsed_deps.append(
                        {"ecosystem": "maven", "package": pkg_name, "version": pkg_version.text}
                    )
    except Exception:
        pass
    return parsed_deps

def parse_go(file_path: str) -> List[Dict[str, str]]:
    parsed_deps = []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            file_content = f.read()
            regex_matches = re.findall(r"([a-zA-Z0-9.\-_/]+)\s+v([0-9a-zA-Z.\-_]+)", file_content)

            for pkg_name, pkg_version in regex_matches:
                if pkg_name != "go":
                    parsed_deps.append({"ecosystem": "go", "package": pkg_name, "version": pkg_version})
    except Exception:
        pass
    return parsed_deps

def parse_ruby(file_path: str) -> List[Dict[str, str]]:
    parsed_deps = []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()

                if line.startswith("gem "):
                    regex_match = re.search(
                        r"""gem\s+['"]([^'"]+)['"](?:\s*,\s*['"]([^'"]+)['"])?""", line
                    )

                    if regex_match:
                        pkg_name = regex_match.group(1)
                        pkg_version = regex_match.group(2) if regex_match.group(2) else ""
                        pkg_version = re.sub(r"^[~>=<\s]+", "", pkg_version)

                        parsed_deps.append(
                            {"ecosystem": "rubygems", "package": pkg_name, "version": pkg_version}
                        )
    except Exception:
        pass
    return parsed_deps

def parse_csproj(file_path: str) -> List[Dict[str, str]]:
    parsed_deps = []
    try:
        xml_tree = ET.parse(file_path)
        xml_root = xml_tree.getroot()

        for pkg_node in xml_root.findall(".//PackageReference"):
            pkg_name = pkg_node.get("Include")
            pkg_version = pkg_node.get("Version")

            if pkg_name and pkg_version:
                parsed_deps.append({"ecosystem": "nuget", "package": pkg_name, "version": pkg_version})
    except Exception:
        pass
    return parsed_deps

def parse_nuget(file_path: str) -> List[Dict[str, str]]:
    parsed_deps = []
    try:
        xml_tree = ET.parse(file_path)
        xml_root = xml_tree.getroot()

        for pkg_node in xml_root.findall(".//package"):
            pkg_name = pkg_node.get("id")
            pkg_version = pkg_node.get("version")

            if pkg_name and pkg_version:
                parsed_deps.append({"ecosystem": "nuget", "package": pkg_name, "version": pkg_version})
    except Exception:
        pass
    return parsed_deps

def parse(target_path: str) -> List[Dict[str, str]]:
    dir_path = Path(target_path)

    if not dir_path.exists() or not dir_path.is_dir():
        raise ValueError(f"[!] The path is invalid: {target_path}")

    parsed_deps = []

    for root_dir, sub_dirs, file_list in os.walk(dir_path):
        sub_dirs[:] = [sub for sub in sub_dirs if sub not in EXCLUDES]

        for file_name in file_list:
            full_path = os.path.join(root_dir, file_name)

            if file_name in DEPS:
                if file_name == "composer.json":
                    parsed_deps.extend(parse_php(full_path))
                elif file_name == "package.json":
                    parsed_deps.extend(parse_npm(full_path))
                elif file_name == "requirements.txt":
                    parsed_deps.extend(parse_pypi(full_path))
                elif file_name == "pom.xml":
                    parsed_deps.extend(parse_maven(full_path))
                elif file_name == "go.mod":
                    parsed_deps.extend(parse_go(full_path))
                elif file_name == "Gemfile":
                    parsed_deps.extend(parse_ruby(full_path))
                elif file_name == "packages.config":
                    parsed_deps.extend(parse_nuget(full_path))
            elif file_name.endswith(".csproj"):
                parsed_deps.extend(parse_csproj(full_path))

    return parsed_deps

from cli.views import logger

def report(parsed_deps: List[Dict[str, str]]):
    logger.section("DEPENDENCIES")

    if not parsed_deps:
        logger.warning("No dependencies found!")
        return

    from cli.views.logger import console
    console.print(f"  [cyan]{len(parsed_deps)}[/cyan] dependencies detected")
    console.print()
    for dep_item in parsed_deps:
        console.print(f"  ├─ [magenta]{dep_item['ecosystem']}[/magenta] [blue]{dep_item['package']}[/blue] v{dep_item['version']}")
