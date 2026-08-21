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

# Hàm nhận dạng ngôn ngữ lập trình
def detect_langs(target: str) -> Dict[str, int]:
    path = Path(target)

    if not path.exists() or not path.is_dir():
        raise ValueError(f"[!] The path is invalid: {target}")

    counts = {}

    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in EXCLUDES]

        for file in files:
            ext = Path(file).suffix.lower()

            if ext in EXTS:
                lang = EXTS[ext]
                counts[lang] = counts.get(lang, 0) + 1

    return counts

import subprocess

# Hàm lấy phiên bản của ngôn ngữ lập trình
def get_versions(counts: Dict[str, int]) -> Dict[str, str]:
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
    
    for lang in counts.keys():

        if lang in cmds:

            try:
                res = subprocess.run(cmds[lang], capture_output=True, text=True, timeout=5)
                out = res.stdout.strip() if res.stdout.strip() else res.stderr.strip()

                if out:
                    versions[lang] = out.split('\n')[0].strip()

                else:
                    versions[lang] = "Unknown"

            except (FileNotFoundError, subprocess.TimeoutExpired):
                versions[lang] = "Not Installed"
                
    return versions

from cli.views import logger

# Hàm báo cáo kết quả
def report_langs(counts: Dict[str, int], versions: Dict[str, str] = None):
    logger.section("LANGUAGES")

    if not counts:
        logger.warning("No source code found.")
        return

    from cli.views.logger import console
    items = sorted(counts.items(), key=lambda i: i[1], reverse=True)
    
    console.print(f"  [cyan]{len(counts)}[/cyan] languages detected")
    console.print()

    for lang, count in items:
        msg = ""

        if versions and lang in versions:
            ver = versions[lang]
            short = ver[:30] + "..." if len(ver) > 30 else ver
            msg = f" [dim]- Runtime: {short}[/dim]"
            
        console.print(f"  - [yellow]{lang.capitalize()}[/yellow]: {count} files{msg}")