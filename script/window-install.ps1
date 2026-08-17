$ErrorActionPreference = "Stop"

# Constants
$RepoOwner = "Hugnd-UIT"
$RepoName = "AI-Based-Static-Application-Security-Testing"
$ExeName = "sinful.exe"
$DownloadUrl = "https://github.com/$RepoOwner/$RepoName/releases/latest/download/$ExeName"
$InstallDir = "$env:USERPROFILE\.sinful"
$ExePath = "$InstallDir\$ExeName"

function Write-Color {
    param (
        [string]$Text,
        [string]$Color = "White",
        [switch]$NoNewline
    )
    if ($NoNewline) {
        Write-Host $Text -NoNewline -ForegroundColor $Color
    } else {
        Write-Host $Text -ForegroundColor $Color
    }
}

Write-Host ""
Write-Color "╭────────────────────────────────────────────────────────────────────╮" "Cyan"
Write-Color "│ SINFUL SAST · INSTALLER                                            │" "Cyan"
Write-Color "│ Command-line SAST                                                  │" "DarkGray"
Write-Color "╰────────────────────────────────────────────────────────────────────╯" "Cyan"
Write-Host ""
Write-Color "━━━ INSTALLATION ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" "Cyan"
Write-Host ""

# Directory
Write-Color "├─ Directory" "White"
Write-Color "│  └─ $InstallDir" "DarkGray"
Write-Color "│" "White"
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
}

# Release
Write-Color "├─ Release" "White"
Write-Color "│  ├─ Channel      " "DarkGray" -NoNewline
Write-Color "latest" "DarkGray"
Write-Color "│  └─ Package      " "DarkGray" -NoNewline
Write-Color "$ExeName" "DarkGray"
Write-Color "│" "White"

# Download
Write-Color "├─ Download" "White"
$DownloadSuccess = $false
try {
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $ExePath -UseBasicParsing
    Write-Color "│  └─ " "White" -NoNewline
    Write-Color "✓ COMPLETED" "Green"
    $DownloadSuccess = $true
} catch {
    Write-Color "│  └─ " "White" -NoNewline
    Write-Color "✖ FAILED" "Red"
}
Write-Color "│" "White"

# PATH
$PathConfigured = $false
$PathStatus = "─ NOT CONFIGURED"
$PathColor = "DarkGray"

if ($DownloadSuccess) {
    $UserPath = [Environment]::GetEnvironmentVariable("PATH", "User")
    if ($UserPath -notlike "*$InstallDir*") {
        $NewPath = "$UserPath;$InstallDir"
        [Environment]::SetEnvironmentVariable("PATH", $NewPath, "User")
        $env:PATH = "$env:PATH;$InstallDir"
        $PathStatus = "✓ ADDED"
        $PathColor = "Green"
    } else {
        $PathStatus = "✓ ALREADY CONFIGURED"
        $PathColor = "Green"
    }
}

Write-Color "└─ PATH" "White"
Write-Color "   └─ " "White" -NoNewline
Write-Color "$PathStatus" "$PathColor"

Write-Host ""
Write-Host ""
Write-Color "━━━ STATUS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" "Cyan"
Write-Host ""

if (-not $DownloadSuccess) {
    Write-Color "✖ INSTALLATION FAILED" "Red"
    Write-Host ""
    Write-Color "├─ Sinful" "White"
    Write-Color "│  └─ " "White" -NoNewline
    Write-Color "✖ Installation could not be completed" "Red"
    Write-Color "│" "White"
    Write-Color "└─ Reason" "White"
    Write-Color "   └─ " "White" -NoNewline
    Write-Color "Unable to download the latest release" "DarkGray"
    Write-Host ""
    Write-Color "Please check your network connection and try again." "DarkGray"
    Write-Host ""
    Write-Color "Exit code: 1" "DarkGray"
    exit 1
}

# Check Dependencies
$HasDependencies = $true
if (-not (Get-Command "semgrep" -ErrorAction SilentlyContinue)) {
    $HasDependencies = $false
    Write-Color "    -> [!] Semgrep not found. Please install Python and run: pip install semgrep" -ForegroundColor Yellow
}
if (-not (Get-Command "git" -ErrorAction SilentlyContinue)) {
    $HasDependencies = $false
    Write-Color "    -> [!] Git not found. Needed for scanning remote URLs." -ForegroundColor Yellow
}

if ($HasDependencies) {
    Write-Color "✓ INSTALLATION COMPLETE" "Green"
    Write-Host ""
    Write-Color "├─ Sinful" "White"
    Write-Color "│  └─ " "White" -NoNewline
    Write-Color "✓ Installed successfully" "Green"
    Write-Color "│" "White"
    Write-Color "└─ Environment" "White"
    Write-Color "   └─ " "White" -NoNewline
    Write-Color "✓ Ready" "Green"
    Write-Host ""
} else {
    Write-Color "⚠ INSTALLATION COMPLETE" "Yellow"
    Write-Host ""
    Write-Color "├─ Sinful" "White"
    Write-Color "│  └─ " "White" -NoNewline
    Write-Color "✓ Installed successfully" "Green"
    Write-Color "│" "White"
    Write-Color "└─ Environment" "White"
    Write-Color "   └─ " "White" -NoNewline
    Write-Color "⚠ Some dependencies are missing" "Yellow"
    Write-Host ""
    Write-Color "Sinful was installed successfully, but some dependencies are missing." "DarkGray"
    Write-Host ""
}

Write-Color "Run: " "White" -NoNewline
Write-Color "sinful" "Green"
Write-Host ""
