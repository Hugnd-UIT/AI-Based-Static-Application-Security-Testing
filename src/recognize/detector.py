import os
from pathlib import Path
from typing import Dict

EXTS = {
    ".php": "php",
    ".js": "javascript",
    ".ts": "typescript",
    ".py": "python",
    ".java": "java",
    ".rb": "ruby",
    ".go": "go",
    ".cs": "c#",
    ".c": "c",
    ".cpp": "c++",
    ".cc": "c++",
    ".h": "c",
}

EXCLUDES = {
    ".git",
    ".idea",
    ".vscode",
    "venv",
    ".venv",
    "env",
    "__pycache__",
    ".pytest_cache",
    ".tox",
    "node_modules",
    "dist",
    "build",
    "coverage",
    ".next",
    "vendor",
    "target",
    ".gradle",
    "bin",
    "obj",
}

def detect(target_path: str) -> Dict[str, int]:
    dir_path = Path(target_path)

    if not dir_path.exists() or not dir_path.is_dir():
        raise ValueError(f"[!] The path is invalid: {target_path}")

    lang_counts = {}

    for root_dir, sub_dirs, file_list in os.walk(dir_path):
        sub_dirs[:] = [sub for sub in sub_dirs if sub not in EXCLUDES]

        for file_name in file_list:
            file_ext = Path(file_name).suffix.lower()

            if file_ext in EXTS:
                lang_name = EXTS[file_ext]
                lang_counts[lang_name] = lang_counts.get(lang_name, 0) + 1

    return lang_counts

import subprocess

def get_versions(lang_counts: Dict[str, int]) -> Dict[str, str]:
    versions = {}
    cmds = {
        "php": ["php", "-v"],
        "javascript": ["node", "-v"],
        "typescript": ["node", "-v"],
        "python": ["python", "--version"],
        "java": ["java", "-version"],
        "ruby": ["ruby", "-v"],
        "go": ["go", "version"],
        "c#": ["dotnet", "--version"],
        "c": ["gcc", "--version"],
        "c++": ["g++", "--version"],
    }
    
    for lang in lang_counts.keys():
        if lang in cmds:
            try:
                cmd_result = subprocess.run(cmds[lang], capture_output=True, text=True, timeout=5)
                # stdout for python/node/php/go, stderr for java
                output = cmd_result.stdout.strip() if cmd_result.stdout.strip() else cmd_result.stderr.strip()
                if output:
                    versions[lang] = output.split('\n')[0].strip()
                else:
                    versions[lang] = "Unknown"
            except (FileNotFoundError, subprocess.TimeoutExpired):
                versions[lang] = "Not Installed"
                
    return versions

from cli.views import logger

def report(lang_counts: Dict[str, int], lang_versions: Dict[str, str] = None):
    logger.section("LANGUAGES")

    if not lang_counts:
        logger.warning("No source code found.")
        return

    from cli.views.logger import console
    sorted_langs = sorted(lang_counts.items(), key=lambda item: item[1], reverse=True)
    
    console.print(f"  [cyan]{len(lang_counts)}[/cyan] languages detected")
    console.print()
    for lang_name, file_count in sorted_langs:
        version_str = ""
        if lang_versions and lang_name in lang_versions:
            v = lang_versions[lang_name]
            v_short = v[:30] + "..." if len(v) > 30 else v
            version_str = f" [dim] - Runtime: {v_short}[/dim]"
            
        console.print(f"  ├─ [yellow]{lang_name.capitalize()}[/yellow]: {file_count} files{version_str}")
