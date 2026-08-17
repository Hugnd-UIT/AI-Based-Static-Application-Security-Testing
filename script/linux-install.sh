#!/usr/bin/env bash

set -e

REPO_OWNER="Hugnd-UIT"
REPO_NAME="AI-Based-Static-Application-Security-Testing"
EXE_NAME="sinful-linux"
DOWNLOAD_URL="https://github.com/$REPO_OWNER/$REPO_NAME/releases/latest/download/$EXE_NAME"
INSTALL_DIR="$HOME/.sinful"
EXE_PATH="$INSTALL_DIR/sinful"

CYAN="\033[36m"
GREEN="\033[32m"
YELLOW="\033[33m"
RED="\033[31m"
DIM="\033[90m"
WHITE="\033[0m"
BOLD_WHITE="\033[97m"

echo ""
echo -e "${CYAN}╭────────────────────────────────────────────────────────────────────╮${WHITE}"
echo -e "${CYAN}│ SINFUL SAST · INSTALLER                                            │${WHITE}"
echo -e "${DIM}│ Command-line SAST                                                  │${WHITE}"
echo -e "${CYAN}╰────────────────────────────────────────────────────────────────────╯${WHITE}"
echo ""
echo -e "${CYAN}━━━ INSTALLATION ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${WHITE}"
echo ""

# Directory
echo -e "├─ Directory"
echo -e "${DIM}│  └─ $INSTALL_DIR${WHITE}"
echo -e "│"
mkdir -p "$INSTALL_DIR"

# Release
echo -e "├─ Release"
echo -e "${DIM}│  ├─ Channel      latest${WHITE}"
echo -e "${DIM}│  └─ Package      $EXE_NAME${WHITE}"
echo -e "│"

# Download
echo -e "├─ Download"
DOWNLOAD_SUCCESS=false
if curl -fsSL "$DOWNLOAD_URL" -o "$EXE_PATH" 2>/dev/null; then
    chmod +x "$EXE_PATH"
    echo -e "│  └─ ${GREEN}✓ COMPLETED${WHITE}"
    DOWNLOAD_SUCCESS=true
else
    echo -e "│  └─ ${RED}✖ FAILED${WHITE}"
fi
echo -e "│"

# PATH
PATH_STATUS="─ NOT CONFIGURED"
PATH_COLOR="$DIM"

SHELL_RC="$HOME/.bashrc"
if [ -n "$ZSH_VERSION" ] || [[ "$SHELL" == *"zsh"* ]]; then
    SHELL_RC="$HOME/.zshrc"
fi

if [ "$DOWNLOAD_SUCCESS" = true ]; then
    if ! grep -q "$INSTALL_DIR" "$SHELL_RC" 2>/dev/null; then
        echo "export PATH=\"$INSTALL_DIR:\$PATH\"" >> "$SHELL_RC"
        PATH_STATUS="✓ ADDED"
        PATH_COLOR="$GREEN"
    else
        PATH_STATUS="✓ ALREADY CONFIGURED"
        PATH_COLOR="$GREEN"
    fi
fi

echo -e "└─ PATH"
echo -e "   └─ ${PATH_COLOR}${PATH_STATUS}${WHITE}"

echo ""
echo ""
echo -e "${CYAN}━━━ STATUS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${WHITE}"
echo ""

if [ "$DOWNLOAD_SUCCESS" = false ]; then
    echo -e "${RED}✖ INSTALLATION FAILED${WHITE}"
    echo ""
    echo -e "├─ Sinful"
    echo -e "│  └─ ${RED}✖ Installation could not be completed${WHITE}"
    echo -e "│"
    echo -e "└─ Reason"
    echo -e "   └─ ${DIM}Unable to download the latest release${WHITE}"
    echo ""
    echo -e "${DIM}Please check your network connection and try again.${WHITE}"
    echo ""
    echo -e "${DIM}Exit code: 1${WHITE}"
    exit 1
fi

# Check Semgrep
HAS_DEPENDENCIES=true
if ! command -v semgrep >/dev/null 2>&1; then
    HAS_DEPENDENCIES=false
    echo -e "${YELLOW}    -> [!] Semgrep not found. Run: pip install semgrep${WHITE}"
fi
if ! command -v git >/dev/null 2>&1; then
    HAS_DEPENDENCIES=false
    echo -e "${YELLOW}    -> [!] Git not found. Needed for scanning remote URLs.${WHITE}"
fi

if [ "$HAS_DEPENDENCIES" = true ]; then
    echo -e "${GREEN}✓ INSTALLATION COMPLETE${WHITE}"
    echo ""
    echo -e "├─ Sinful"
    echo -e "│  └─ ${GREEN}✓ Installed successfully${WHITE}"
    echo -e "│"
    echo -e "└─ Environment"
    echo -e "   └─ ${GREEN}✓ Ready${WHITE}"
    echo ""
else
    echo -e "${YELLOW}⚠ INSTALLATION COMPLETE${WHITE}"
    echo ""
    echo -e "├─ Sinful"
    echo -e "│  └─ ${GREEN}✓ Installed successfully${WHITE}"
    echo -e "│"
    echo -e "└─ Environment"
    echo -e "   └─ ${YELLOW}⚠ Some dependencies are missing${WHITE}"
    echo ""
    echo -e "${DIM}Sinful was installed successfully, but some dependencies are missing.${WHITE}"
    echo ""
fi

echo -e "${DIM}Run: ${BOLD_WHITE}sinful${WHITE}"
echo ""
